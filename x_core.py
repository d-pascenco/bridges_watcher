import os, re, time, csv, json, pickle, logging, imaplib, email, requests
from collections import defaultdict
from datetime import timezone
from email.utils import parsedate_to_datetime
from email.header import decode_header, make_header
from bs4 import BeautifulSoup
import pathlib, dotenv

BASE        = pathlib.Path(__file__).resolve().parent
CFG_PATH    = BASE / 'parser_config.csv'
ENV_PATH    = BASE / '.env'
UID_PATH    = BASE / 'xcore_uid.pkl'
LOG_PATH    = BASE / 'xcore.log'

logging.basicConfig(filename=LOG_PATH, level=logging.INFO, encoding='utf-8',
                    format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger()

# ─────────── logging helpers ───────────
def debug_log(message):
    """Emit debug messages only when DEBUG_EMAIL=1."""
    try:
        if ENV.get('DEBUG_EMAIL'):
            logger.debug(message)
    except Exception:
        logger.debug(message)

# ─────────── .env hot-load ───────────
def load_env():
    if ENV_PATH.exists():
        dotenv.load_dotenv(ENV_PATH)
    return {
        'IMAP_SERVER': os.getenv('IMAP_HOST'),
        'IMAP_USER'  : os.getenv('IMAP_USER'),
        'IMAP_PASS'  : os.getenv('IMAP_PASS'),
        'SLACK_URL'  : os.getenv('SLACK_URL'),
        'CHECK_SEC'  : int(os.getenv('CHECK_SEC', '10')),
    }

ENV = load_env()

# ─────────── helpers ───────────
def load_uids():
    try:
        with open(UID_PATH, 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        return set()
    except Exception:
        logger.exception('uid load')
        return set()

def save_uids(u):
    try:
        with open(UID_PATH, 'wb') as f:
            pickle.dump(u, f)
    except Exception:
        logger.exception('uid save')

def slack(msg):
    try:
        r = requests.post(ENV['SLACK_URL'], json={'text': msg}, timeout=10)
        r.raise_for_status()
        return True
    except Exception:
        logger.exception('slack err')
        return False

def html2text(html):
    text = BeautifulSoup(html, 'html.parser').get_text(separator='\n')
    text = text.replace('\xa0', ' ')
    return re.sub(r'\n{2,}', '\n', text)

def body(msg):
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_maintype() == 'multipart':
                continue
            if 'attachment' in str(p.get('Content-Disposition', '')).lower():
                continue
            raw = p.get_payload(decode=True) or b''
            t = raw.decode(errors='replace')
            return t if p.get_content_type() == 'text/plain' else html2text(t)
    raw = msg.get_payload(decode=True) or b''
    t = raw.decode(errors='replace')
    return t if msg.get_content_type() == 'text/plain' else html2text(t)

def parse_email_ts(value):
    if not value:
        return ''
    try:
        dt = parsedate_to_datetime(value)
        if dt is None:
            return ''
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.replace(microsecond=0)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''

def decode_header_value(value):
    if not value:
        return ''
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        if isinstance(value, bytes):
            for enc in ('utf-8', 'latin1'):
                try:
                    return value.decode(enc)
                except Exception:
                    continue
            return value.decode(errors='ignore')
        if isinstance(value, str):
            try:
                return value.encode('latin1').decode('utf-8')
            except Exception:
                return value
        return str(value)

def parse_config(p):
    with open(p, 'r', encoding='utf-8') as f:
        sample = f.read(4096)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=',;\t')
        reader = csv.DictReader(f, dialect=dialect)
        cfgs = []
        for r in reader:
            try:
                pattern_raw = (r.get('pattern') or '').strip()
                if not pattern_raw:
                    raise ValueError('empty pattern')
                r['pattern'] = re.compile(pattern_raw, re.S)

                r['field_map'] = json.loads((r.get('field_map') or '').strip() or '{}')

                exclude_raw = r.get('exclude_fields') or ''
                r['exclude_fields'] = {part.strip() for part in exclude_raw.split(',') if part.strip()}

                theme_raw = (r.get('email_theme') or '').strip()
                r['email_theme'] = re.compile(theme_raw) if theme_raw else None

                strip_raw = (r.get('strip_pattern') or '').strip()
                r['strip_pattern'] = re.compile(strip_raw, re.S | re.I) if strip_raw else None

                trunc_raw = (r.get('truncate_pattern') or '').strip()
                r['truncate_pattern'] = re.compile(trunc_raw) if trunc_raw else None
                cfgs.append(r)
            except Exception as exc:
                logger.warning(f'bad cfg row skipped: {r} | err={exc}')
        logger.info(f'Loaded {len(cfgs)} rules')
        return cfgs

def extract(text, sender, subj, cfgs, msg_date=''):
    out = []
    diagnostics = []
    for c in cfgs:
        rule_name = c.get('name', '<unnamed>')

        if c.get('email_address') and c['email_address'] not in sender:
            diagnostics.append(f'rule={rule_name} | email_address filter "{c["email_address"]}" not in "{sender}"')
            continue
        if c.get('email_theme') and not c['email_theme'].search(subj or ''):
            diagnostics.append(f'rule={rule_name} | email_theme {c["email_theme"].pattern!r} did not match subject')
            continue

        local_txt = c['strip_pattern'].sub('', text) if c.get('strip_pattern') else text
        if c.get('strip_pattern') and ENV.get('DEBUG_EMAIL'):
            debug_log(f'rule={rule_name} | strip_pattern removed tail: len(text) {len(text)} -> {len(local_txt)}')

        status_hint = ''
        status_match = re.search(r'^\s*(Active alerts|Resolved)', local_txt, re.I | re.M)
        if status_match:
            status_hint = status_match.group(1)

        matches = list(c['pattern'].finditer(local_txt))
        if not matches:
            snippet = local_txt.strip()
            if len(snippet) > 400:
                snippet = snippet[:400] + '…'
            clean_snippet = snippet.replace('\r', '').replace('\n', '\\n')
            diagnostics.append(f'rule={rule_name} | regex produced no matches | snippet="{clean_snippet}"')
            continue

        for idx, m in enumerate(matches, 1):
            g = m.groupdict()
            rest = g.get('rest', '')

            if c.get('strip_pattern'):
                rest = c['strip_pattern'].sub('', rest)

            if c.get('truncate_pattern'):
                cut = c['truncate_pattern'].search(rest)
                if cut:
                    rest = rest[:cut.start()].rstrip()

            rest = rest.strip()
            generates_rest = 'rest' in c.get('field_map', {})
            if not rest and not generates_rest:
                diagnostics.append(f'rule={rule_name} | match {idx}: empty rest after processing and no generator')
                continue

            g['rest'] = rest
            loc = g.copy()
            loc.setdefault('email_ts', msg_date or '')
            loc.setdefault('email_subject', subj or '')
            loc.setdefault('email_from', sender or '')
            loc.setdefault('status_hint', status_hint)
            loc.setdefault('status_value', (g.get('status') or status_hint or '').strip())
            for k, expr in c['field_map'].items():
                try:
                    loc[k] = eval(expr, {}, loc)
                except Exception:
                    diagnostics.append(f'rule={rule_name} | match {idx}: field_map key={k} failed for expr={expr!r}')
                    loc[k] = ''
            if isinstance(loc.get('rest'), str):
                loc['rest'] = loc['rest'].strip()
            if not loc.get('rest'):
                diagnostics.append(f'rule={rule_name} | match {idx}: rest empty after processing, skipping')
                continue
            out.append({**c, **loc})
    return out, diagnostics

# ─────────── aggregation ───────────
def aggregate_logs(logs):
    groups = defaultdict(list)
    for l in logs:
        key = (l.get('name'), l.get('lvl'), l.get('stat'))
        groups[key].append(l)
    res = []
    for grp in groups.values():
        if len(grp) == 1:
            res.append(grp[0])
        else:
            base = grp[0].copy()
            base['rest'] = "\n".join(x['rest'] for x in grp)
            res.append(base)
    debug_log(f'aggregate_logs | input={len(logs)} grouped={len(res)}')
    return res

# ─────────── slack format ───────────
def make_slack(l):
    excl = l.get('exclude_fields', set())
    d = {k: v for k, v in l.items() if k not in excl}
    try:
        msg = d['slack_format'].format(**d)
    except KeyError as e:
        logger.error(f'fmt key {e}')
        msg = 'FORMAT ERROR'
    if d.get('note'):
        msg += f'\n*ACTIONS:* {d["note"]}'
    msg = msg.replace(r'\n', '\n')
    return '> ' + '\n> '.join(msg.strip().splitlines())

def log_decision(uid, frm, subj, cfg, sent, why=''):
    status = 'SENT' if sent else 'SKIPPED'
    rule = cfg or 'no-match'
    reason = f' | reason={why}' if why else ''
    if sent:
        logger.debug(f'[EMAIL] UID={uid} | {status} | rule={rule} | from="{frm}" | subj="{subj}"{reason}')
    else:
        logger.warning(f'[EMAIL] UID={uid} | {status} | rule={rule} | from="{frm}" | subj="{subj}"{reason}')

def log_skip_report(uid, frm, subj, body_text, diagnostics, msg_ts=''):
    preview = (body_text or '').replace('\r', '')
    preview = preview.strip()
    limit = 1200
    truncated = False
    if len(preview) > limit:
        preview = preview[:limit]
        truncated = True
    if truncated:
        preview += '…'
    diag_lines = diagnostics or ['no rule reported additional diagnostics']
    diag_text = '\n'.join(f'  - {line}' for line in diag_lines)
    ts_part = f' | date={msg_ts}' if msg_ts else ''
    logger.warning(
        f'[EMAIL] UID={uid} | SKIP DETAIL{ts_part} | from="{frm}" | subj="{subj}"\n'
        f'BODY PREVIEW:\n{preview}\nRULE CHECKS:\n{diag_text}'
    )

# ─────────── main mailbox loop ───────────
def process_box(conn, done, cfgs):
    logger.debug('Scanning mailbox for new emails')
    st, data = conn.uid('search', None, 'ALL')
    if st != 'OK':
        logger.error(f'IMAP search failed with status: {st}')
        return 0
    all_uids = [u.decode() for u in data[0].split()]
    new = [u for u in all_uids if u not in done]
    if new:
        logger.info(f'Found {len(new)} new email(s) (total in mailbox: {len(all_uids)})')
    else:
        logger.debug(f'No new emails (total in mailbox: {len(all_uids)})')
    processed_total = 0
    sent_total = 0
    for uid in new:
        frm = subj = ''
        try:
            processed_total += 1
            logger.debug(f'Fetching email UID={uid}')
            st, md = conn.uid('fetch', uid, '(RFC822)')
            if st != 'OK':
                log_decision(uid, frm, subj, None, False, f'fetch status {st}')
                continue
            msg = email.message_from_bytes(md[0][1])
            frm = decode_header_value(msg.get('From', ''))
            subj = decode_header_value(msg.get('Subject', ''))
            msg_ts = parse_email_ts(msg.get('Date'))
            txt = body(msg)
            matches, diag = extract(txt, frm, subj, cfgs, msg_date=msg_ts)
            logs = aggregate_logs(matches)
            if not logs:
                log_decision(uid, frm, subj, None, False, 'no matching rule')
                log_skip_report(uid, frm, subj, txt, diag, msg_ts)
                continue
            ok = True
            for lg in logs:
                res = slack(make_slack(lg))
                ok &= res
                reason = 'delivered to Slack' if res else 'Slack err'
                log_decision(uid, frm, subj, lg.get('name'), res, reason)
            if ok:
                done.add(uid)
                sent_total += 1
        except Exception as e:
            logger.exception(f'uid {uid}')
            log_decision(uid, frm, subj, None, False, f'exc:{e}')
    skipped = max(processed_total - sent_total, 0)
    logger.info(f'Cycle summary: processed={processed_total}, sent={sent_total}, skipped={skipped}')
    return sent_total

def main():
    done = load_uids()
    cfgs = parse_config(CFG_PATH)
    cfg_mtime = os.path.getmtime(CFG_PATH)
    env_mtime = ENV_PATH.stat().st_mtime if ENV_PATH.exists() else None

    while True:
        # hot-reload CSV
        new_cfg_mtime = os.path.getmtime(CFG_PATH)
        if new_cfg_mtime != cfg_mtime:
            cfgs = parse_config(CFG_PATH)
            cfg_mtime = new_cfg_mtime
            logger.info('parser_config.csv reloaded')

        # hot-reload .env
        if ENV_PATH.exists():
            new_env_mtime = ENV_PATH.stat().st_mtime
            if new_env_mtime != env_mtime:
                globals()['ENV'] = load_env()
                env_mtime = new_env_mtime
                logger.info('.env reloaded')

        try:
            with imaplib.IMAP4_SSL(ENV['IMAP_SERVER']) as im:
                im.login(ENV['IMAP_USER'], ENV['IMAP_PASS'])
                im.select('INBOX')
                if process_box(im, done, cfgs):
                    save_uids(done)
        except Exception:
            logger.exception('imap loop')

        time.sleep(ENV['CHECK_SEC'])

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
