import os, re, time, csv, json, pickle, logging, imaplib, email, requests
import argparse
import sys
from email.utils import parsedate_to_datetime
from collections import defaultdict, Counter
from bs4 import BeautifulSoup
import pathlib, dotenv
from urllib.parse import urlparse
import unicodedata
import hashlib

BASE        = pathlib.Path(__file__).resolve().parent
CFG_PATH    = BASE / 'parser_config.csv'
ENV_PATH    = BASE / '.env'
UID_PATH    = BASE / 'xcore_uid.pkl'
LOG_PATH    = BASE / 'xcore.log'

logging.basicConfig(filename=LOG_PATH, level=logging.DEBUG, encoding='utf-8',
                    format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger()

# ─────────── .env hot-load ───────────
ENV_META = {}


def load_env():
    existing_env = dict(os.environ)
    file_values = {}
    meta = {}

    if ENV_PATH.exists():
        try:
            raw_values = dotenv.dotenv_values(ENV_PATH)
            file_values = {k: v for k, v in raw_values.items() if v is not None}
        except Exception:
            logger.exception('.env parse failed')
            file_values = {}

    def _fingerprint(value):
        if not value:
            return 'missing'
        return hashlib.sha256(str(value).encode('utf-8')).hexdigest()[:16]

    def resolve(key, default=None):
        if key in file_values:
            value = file_values[key]
            previous = existing_env.get(key)
            if previous is not None and previous != value:
                if key == 'SLACK_URL':
                    logger.debug(
                        'env override: SLACK_URL replaced existing value (old_fingerprint=%s new_fingerprint=%s)',
                        _fingerprint(previous),
                        _fingerprint(value),
                    )
                else:
                    logger.debug('env override: %s replaced existing value', key)
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
            meta[key] = '.env'
            return value if value not in (None, '') else default

        value = existing_env.get(key)
        if value is not None:
            meta[key] = 'env'
            return value

        meta[key] = 'missing'
        return default

    imap_server = resolve('IMAP_HOST')
    imap_user = resolve('IMAP_USER')
    imap_pass = resolve('IMAP_PASS')
    slack_url = resolve('SLACK_URL')
    slack_bot_token = resolve('SLACK_BOT_TOKEN')
    slack_channel = resolve('SLACK_CHANNEL')

    raw_check_sec = resolve('CHECK_SEC', '10')
    try:
        check_sec = int(raw_check_sec)
    except (TypeError, ValueError):
        logger.warning('invalid CHECK_SEC=%r; defaulting to 10', raw_check_sec)
        check_sec = 10

    debug_email_flag = resolve('DEBUG_EMAIL', '0')
    debug_email = str(debug_email_flag) == '1'

    env = {
        'IMAP_SERVER': imap_server,
        'IMAP_USER'  : imap_user,
        'IMAP_PASS'  : imap_pass,
        'SLACK_URL'  : slack_url,
        'SLACK_BOT_TOKEN': slack_bot_token,
        'SLACK_CHANNEL'  : slack_channel,
        'CHECK_SEC'  : check_sec,
        'DEBUG_EMAIL': debug_email,
    }

    if meta.get('SLACK_URL') == 'env' and 'SLACK_URL' not in file_values:
        logger.info('SLACK_URL loaded from process environment (no override in .env)')
    elif meta.get('SLACK_URL') == 'missing':
        logger.warning('SLACK_URL not configured in environment or .env')

    if env.get('SLACK_BOT_TOKEN') and not env.get('SLACK_CHANNEL'):
        logger.warning('SLACK_BOT_TOKEN configured but SLACK_CHANNEL missing')
    if env.get('SLACK_CHANNEL') and not env.get('SLACK_BOT_TOKEN'):
        logger.warning('SLACK_CHANNEL configured but SLACK_BOT_TOKEN missing')

    globals()['ENV_META'] = meta
    return env


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


def _describe_hidden_chars(chars):
    if not chars:
        return ''
    counter = Counter(chars)
    parts = []
    for ch, count in counter.items():
        code = f'U+{ord(ch):04X}'
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = 'UNKNOWN'
        if count > 1:
            parts.append(f'{code} {name} x{count}')
        else:
            parts.append(f'{code} {name}')
    return ', '.join(parts)


def _describe_visible_chars(chars):
    if not chars:
        return ''
    seen = []
    for ch in chars:
        code = f'U+{ord(ch):04X}'
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = 'UNKNOWN'
        seen.append(f"{ch!r} ({code} {name})")
    return ', '.join(seen)


def _normalise_slack_url(raw_url):
    if not raw_url:
        return '', []

    trimmed = raw_url.strip().strip('"').strip("'").strip()
    cleaned_chars = []
    removed_chars = []
    for ch in trimmed:
        category = unicodedata.category(ch)
        if ch.isspace() or category in {'Cf', 'Cc', 'Cs', 'Co'}:
            removed_chars.append(ch)
            continue
        cleaned_chars.append(ch)
    cleaned = ''.join(cleaned_chars)
    return cleaned, removed_chars


_SLACK_ID_RE = re.compile(r'^[A-Za-z0-9_-]+$')


def _validate_slack_url(url):
    if not url:
        return False, 'webhook url empty'

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f'cannot parse webhook url ({exc})'

    if parsed.scheme != 'https':
        return False, f'unexpected scheme {parsed.scheme!r}'
    if parsed.netloc != 'hooks.slack.com':
        return False, f'unexpected host {parsed.netloc!r}'

    segments = [seg for seg in parsed.path.split('/') if seg]
    if len(segments) != 4 or segments[0] != 'services':
        return False, 'unexpected path format'

    team_id, channel_id, token = segments[1:4]
    unexpected = []
    for label, value in (('team', team_id), ('channel', channel_id), ('token', token)):
        if not value:
            return False, f'missing {label} segment'
        if not _SLACK_ID_RE.fullmatch(value):
            unexpected.extend([(label, ch) for ch in value if ch not in '-_' and not ch.isalnum()])
    if unexpected:
        bad_desc = _describe_visible_chars([ch for _, ch in unexpected])
        return False, f'unexpected characters in segments: {bad_desc}'

    return True, ''


def _post_to_slack(url, msg):
    r = requests.post(url, json={'text': msg}, timeout=10)
    r.raise_for_status()


def _fingerprint_value(value):
    if not value:
        return 'missing'
    digest = hashlib.sha256(value.encode('utf-8')).hexdigest()
    return digest[:16]


def _log_http_error(exc, fingerprint=None):
    payload = ''
    status = getattr(exc.response, 'status_code', 'no-status')
    if exc.response is not None:
        payload = (exc.response.text or '').strip()
    if fingerprint:
        logger.error('slack err status=%s payload=%s fingerprint=%s', status, payload, fingerprint)
    else:
        logger.error('slack err status=%s payload=%s', status, payload)


def _send_via_slack_webhook(raw_url, msg):
    source = ENV_META.get('SLACK_URL', 'unknown')
    if not raw_url:
        return False, False

    normalised, removed_chars = _normalise_slack_url(raw_url)
    if normalised != raw_url:
        logger.debug('slack webhook url sanitised (quotes/whitespace/hidden chars trimmed)')
    if removed_chars:
        logger.debug('slack webhook sanitised removed_chars=%s', _describe_hidden_chars(removed_chars))

    if not normalised:
        logger.warning('slack skipped: webhook url empty after normalisation')
        return False, True

    ok, reason = _validate_slack_url(normalised)
    if not ok:
        logger.warning('slack skipped: %s', reason)
        return False, True

    try:
        normalised.encode('ascii')
    except UnicodeEncodeError:
        logger.warning('slack skipped: webhook url still contains non-ASCII characters after sanitisation')
        return False, True

    fingerprint = _fingerprint_value(normalised)

    details = _slack_target_details(normalised)
    if details and logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            'slack target host=%s team=%s channel=%s token_len=%s message_chars=%s',
            details['host'] or 'unknown',
            details['team'] or 'unknown',
            details['channel'] or 'unknown',
            details['token_len'],
            len(msg or ''),
        )
        logger.debug('slack webhook fingerprint=%s url_len=%s source=%s', fingerprint, len(normalised), source)
        if raw_url != normalised:
            logger.debug('slack raw webhook fingerprint=%s raw_len=%s (pre-normalisation)', _fingerprint_value(raw_url), len(raw_url))
        if source == 'env':
            logger.debug('slack webhook currently sourced from process environment')
    try:
        _post_to_slack(normalised, msg)
        return True, True
    except requests.exceptions.HTTPError as exc:
        _log_http_error(exc, fingerprint=fingerprint)
        return False, True
    except requests.exceptions.RequestException:
        logger.exception('slack err request-exception')
        return False, True
    except Exception:
        logger.exception('slack err unexpected')
        return False, True


def _post_via_slack_api(token, channel, msg):
    if not token or not channel:
        logger.warning('slack api skipped: bot token or channel missing')
        return False

    token_fp = _fingerprint_value(token)
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            'slack api target channel=%s token_fp=%s message_chars=%s',
            channel,
            token_fp,
            len(msg or ''),
        )

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json; charset=utf-8',
    }
    payload = {
        'channel': channel,
        'text': msg,
    }
    try:
        resp = requests.post('https://slack.com/api/chat.postMessage', headers=headers, json=payload, timeout=10)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        status = getattr(exc.response, 'status_code', 'no-status')
        body = ''
        if exc.response is not None:
            body = (exc.response.text or '').strip()
        logger.error('slack api err status=%s payload=%s token_fp=%s', status, body, token_fp)
        return False
    except requests.exceptions.RequestException:
        logger.exception('slack api err request-exception')
        return False

    try:
        data = resp.json()
    except ValueError:
        logger.error('slack api err non-json response payload=%s', (resp.text or '').strip())
        return False

    if not data.get('ok'):
        logger.error('slack api err ok=%s error=%s', data.get('ok'), data.get('error'))
        return False

    return True


def slack(msg):
    webhook_url = ENV.get('SLACK_URL') or ''
    bot_token = ENV.get('SLACK_BOT_TOKEN') or ''
    channel = ENV.get('SLACK_CHANNEL') or ''

    webhook_sent, webhook_attempted = _send_via_slack_webhook(webhook_url, msg)
    if webhook_sent:
        return True

    if bot_token and channel:
        if webhook_attempted:
            logger.info('slack webhook delivery failed, trying chat.postMessage fallback')
        else:
            logger.info('slack webhook not configured, using chat.postMessage fallback')
        return _post_via_slack_api(bot_token, channel, msg)

    if not webhook_attempted:
        logger.warning('slack skipped: no webhook url configured and no bot token/channel fallback available')

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
        raw_url = ENV.get('SLACK_URL') or ''
        cleaned_url, removed_chars = _normalise_slack_url(raw_url)
        if removed_chars:
            logger.debug('slack webhook sanitised removed_chars=%s', _describe_hidden_chars(removed_chars))
        info = _slack_target_details(cleaned_url)
        if info:
            fingerprint = _fingerprint_value(cleaned_url)
            source = ENV_META.get('SLACK_URL', 'unknown')
            summary = (
                f"Slack webhook host={info['host'] or 'unknown'} "
                f"team={info['team'] or 'unknown'} "
                f"channel={info['channel'] or 'unknown'} "
                f"token_len={info['token_len']} "
                f"fingerprint={fingerprint} "
                f"url_len={len(cleaned_url)} "
                f"source={source}"
            )
            if raw_url and raw_url != cleaned_url:
                summary += (
                    f" raw_fingerprint={_fingerprint_value(raw_url)} "
                    f"raw_len={len(raw_url)}"
                )
        else:
            summary = 'Slack webhook summary unavailable (missing or invalid URL).'
        print(summary)
        logger.info(summary)

        bot_token = ENV.get('SLACK_BOT_TOKEN') or ''
        channel = ENV.get('SLACK_CHANNEL') or ''
        if bot_token or channel:
            fallback_summary = (
                f"Slack API fallback channel={channel or 'missing'} "
                f"token_fp={_fingerprint_value(bot_token)}"
            )
            print(fallback_summary)
            logger.info(fallback_summary)

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
