import os, re, time, csv, json, pickle, logging, imaplib, email, requests
import argparse
import sys
from email.utils import parsedate_to_datetime
from collections import defaultdict
from bs4 import BeautifulSoup
import pathlib, dotenv
from urllib.parse import urlparse

BASE        = pathlib.Path(__file__).resolve().parent
CFG_PATH    = BASE / 'parser_config.csv'
ENV_PATH    = BASE / '.env'
UID_PATH    = BASE / 'xcore_uid.pkl'
LOG_PATH    = BASE / 'xcore.log'

logging.basicConfig(filename=LOG_PATH, level=logging.DEBUG, encoding='utf-8',
                    format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger()

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
        'DEBUG_EMAIL': os.getenv('DEBUG_EMAIL', '0') == '1',
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

def _slack_target_details(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    segments = [seg for seg in parsed.path.split('/') if seg]
    team_id = segments[1] if len(segments) > 1 else ''
    channel_id = segments[2] if len(segments) > 2 else ''
    token_len = len(segments[3]) if len(segments) > 3 else 0
    return {
        'host': parsed.netloc,
        'team': team_id,
        'channel': channel_id,
        'token_len': token_len,
    }


def _post_to_slack(url, msg):
    r = requests.post(url, json={'text': msg}, timeout=10)
    r.raise_for_status()


def _log_http_error(exc):
    payload = ''
    status = getattr(exc.response, 'status_code', 'no-status')
    if exc.response is not None:
        payload = (exc.response.text or '').strip()
    logger.error('slack err status=%s payload=%s', status, payload)


def slack(msg):
    raw_url = ENV.get('SLACK_URL') or ''
    trimmed = raw_url.strip()
    url = trimmed.strip('"').strip("'")
    if not url:
        logger.warning('slack skipped: no webhook url configured')
        return False
    if url != raw_url:
        logger.debug('slack webhook url normalised (whitespace/quotes trimmed)')
    details = _slack_target_details(url)
    if details and logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            'slack target host=%s team=%s channel=%s token_len=%s message_chars=%s',
            details['host'] or 'unknown',
            details['team'] or 'unknown',
            details['channel'] or 'unknown',
            details['token_len'],
            len(msg or ''),
        )
    try:
        _post_to_slack(url, msg)
        return True
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404 and raw_url != url:
            logger.warning('slack normalised URL returned 404, retrying original formatting')
            try:
                _post_to_slack(raw_url, msg)
                logger.info('slack delivered using original URL formatting')
                return True
            except requests.exceptions.HTTPError as retry_exc:
                _log_http_error(retry_exc)
                return False
            except requests.exceptions.RequestException:
                logger.exception('slack err request-exception on retry')
                return False
            except Exception:
                logger.exception('slack err unexpected on retry')
                return False
        _log_http_error(exc)
        return False
    except requests.exceptions.RequestException:
        logger.exception('slack err request-exception')
        return False
    except Exception:
        logger.exception('slack err unexpected')
        return False

def html2text(html):
    return BeautifulSoup(html, 'html.parser').get_text()

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

def kv_blocks(text, start_key='message', keys=None):
    keys = keys or ('message', 'consumer', 'grafana_folder', 'instance', 'priority')
    blocks = []
    current = {}
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or ':' not in stripped:
            continue
        key, value = stripped.split(':', 1)
        key_norm = key.strip().lower()
        if key_norm == start_key and current:
            blocks.append(current)
            current = {}
        if key_norm in keys:
            current[key_norm] = value.strip()
    if current:
        blocks.append(current)
    return blocks

EVAL_GLOBALS = {
    '__builtins__': __builtins__,
    'kv_blocks': kv_blocks,
}

def parse_config(p):
    with open(p, 'r', encoding='utf-8') as f:
        sample = f.read(4096)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=',;\t')
        if getattr(dialect, 'quotechar', '"') != '"':
            dialect.quotechar = '"'
            dialect.doublequote = True
        reader = csv.DictReader(f, dialect=dialect)
        cfgs = []
        for r in reader:
            try:
                r['pattern']          = re.compile(r['pattern'], re.S)
                r['field_map']        = json.loads(r['field_map'] or '{}')
                r['exclude_fields']   = set((r.get('exclude_fields') or '').split(',')) - {''}
                r['email_theme']      = re.compile(r['email_theme'])      if r.get('email_theme')      else None
                r['strip_pattern']    = re.compile(r['strip_pattern'], re.S | re.I) if r.get('strip_pattern') else None
                r['truncate_pattern'] = re.compile(r['truncate_pattern']) if r.get('truncate_pattern') else None
                cfgs.append(r)
            except Exception:
                logger.warning(f'bad cfg row skipped: {r}')
        logger.info(f'Loaded {len(cfgs)} rules')
        return cfgs

def message_timestamp(msg):
    raw = msg.get('Date') if msg else ''
    if not raw:
        return ''
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo:
            dt = dt.astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def extract(text, sender, subj, cfgs, email_ts=''):
    out = []
    for c in cfgs:
        if c.get('email_address') and c['email_address'] not in sender:
            continue
        if c.get('email_theme') and not c['email_theme'].search(subj or ''):
            continue

        local_txt = c['strip_pattern'].sub('', text) if c.get('strip_pattern') else text

        for m in c['pattern'].finditer(local_txt):
            g = m.groupdict()
            rest = g.get('rest', '')

            if c.get('strip_pattern'):
                rest = c['strip_pattern'].sub('', rest)

            if c.get('truncate_pattern'):
                cut = c['truncate_pattern'].search(rest)
                if cut:
                    rest = rest[:cut.start()].rstrip()

            rest = rest.strip()
            if not rest:
                continue

            g['rest'] = rest
            loc = g.copy()
            loc.setdefault('email_ts', email_ts)
            for k, expr in c['field_map'].items():
                try:
                    loc[k] = eval(expr, EVAL_GLOBALS, loc)
                except Exception:
                    loc[k] = ''
            if email_ts and not loc.get('ts'):
                loc['ts'] = email_ts
            out.append({**c, **loc})
    return out

# ─────────── aggregation ───────────
def aggregate_logs(logs):
    groups = defaultdict(list)
    for l in logs:
        groups[l['name']].append(l)
    res = []
    for grp in groups.values():
        if len(grp) == 1:
            res.append(grp[0])
        else:
            base = grp[0].copy()
            base['rest'] = "\n".join(x['rest'] for x in grp)
            res.append(base)
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
    if not ENV['DEBUG_EMAIL']:
        return
    status = 'SENT' if sent else 'SKIPPED'
    rule = cfg or 'no-match'
    logger.debug(f'[EMAIL] UID={uid} | {status} | rule={rule} | from="{frm}" | subj="{subj}" | {why}')

# ─────────── main mailbox loop ───────────
def process_box(conn, done, cfgs):
    st, data = conn.uid('search', None, 'ALL')
    if st != 'OK':
        return 0
    new = [u.decode() for u in data[0].split() if u.decode() not in done]
    sent_total = 0
    for uid in new:
        try:
            st, md = conn.uid('fetch', uid, '(RFC822)')
            if st != 'OK':
                continue
            msg = email.message_from_bytes(md[0][1])
            frm = msg.get('From', '')
            subj = msg.get('Subject', '')
            txt = body(msg)
            msg_ts = message_timestamp(msg)
            logs = aggregate_logs(extract(txt, frm, subj, cfgs, msg_ts))
            if not logs:
                log_decision(uid, frm, subj, None, False, 'no rule')
                continue
            ok = True
            for lg in logs:
                res = slack(make_slack(lg))
                ok &= res
                log_decision(uid, frm, subj, lg.get('name'), res, '' if res else 'Slack err')
            if ok:
                done.add(uid)
                sent_total += 1
        except Exception as e:
            logger.exception(f'uid {uid}')
            log_decision(uid, frm, subj, None, False, f'exc:{e}')
    return sent_total

def main(run_once=False):
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

        if run_once:
            break

        time.sleep(ENV['CHECK_SEC'])

def cli():
    parser = argparse.ArgumentParser(description='Bridges Watcher mailbox processor')
    parser.add_argument(
        '--check-slack',
        nargs='?',
        const='Bridges Watcher Slack connectivity test',
        metavar='MESSAGE',
        help='Send a test message to the configured Slack webhook and exit.',
    )
    parser.add_argument(
        '--slack-info',
        action='store_true',
        help='Print a sanitised summary of the Slack webhook target and exit.',
    )
    parser.add_argument(
        '--run-once',
        action='store_true',
        help='Process the mailbox a single time instead of running endlessly.',
    )
    args = parser.parse_args()

    if args.slack_info:
        info = _slack_target_details(ENV.get('SLACK_URL') or '')
        if info:
            summary = (
                f"Slack webhook host={info['host'] or 'unknown'} "
                f"team={info['team'] or 'unknown'} "
                f"channel={info['channel'] or 'unknown'} "
                f"token_len={info['token_len']}"
            )
        else:
            summary = 'Slack webhook summary unavailable (missing or invalid URL).'
        print(summary)
        logger.info(summary)
        if args.check_slack is None and not args.run_once:
            return

    if args.check_slack is not None:
        message = args.check_slack or 'Bridges Watcher Slack connectivity test'
        print(f'Sending Slack test message: {message!r}')
        ok = slack(message)
        if ok:
            print('Slack test message delivered successfully.')
            logger.info('Slack test message delivered successfully.')
        else:
            print('Slack test message failed. Inspect xcore.log for details.')
            logger.error('Slack test message failed.')
            sys.exit(1)
        if not args.run_once:
            return

    try:
        main(run_once=args.run_once)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    cli()
