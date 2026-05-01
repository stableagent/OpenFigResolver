# OpenFigResolver – DNS Resolver Tester

**OpenFigResolver** is a zero‑dependency Python tool that tests DNS resolvers through multi‑stage validation. It helps network engineers, security researchers, and ordinary users find DNS servers that are honest, uncensored, and fast – especially in environments where the normal internet is heavily manipulated.

## Why I wrote this (the real situation in Iran)

I live in Iran. The internet here has lost its original meaning.

**Cost**: For the general public, one gigabyte of mobile internet costs more than 1.5 US dollars. That is with low speed and many restrictions. And if the rulers give you “internet” – it is an internet with thousands of limitations: no YouTube, no Telegram, no Instagram, no Twitter.

**Manipulation**: The Islamic Republic does not even allow correct, trouble‑free use of GitHub. I have uploaded my files manually because of structured DNS poisoning across the whole country. Every day we move closer to North Korean standards of freedom of speech and basic human rights.

**Confusion**: The general public now calls the **national intranet** “the internet”. They do not know the difference. As a technical person, hearing “the internet is working fine” when you are completely disconnected from the global Internet is deeply frustrating. That word – “internet” – has become one of the most annoying words for a specialist. It can disturb you for hours.

**Justification**: All this harassment is justified in the name of “national security”.

Sometimes, when I think about my fate, I come to the conclusion that we, the people, are imprisoned in a country run by criminals. A government of criminals ruling over the people.

The internet was my wings. It lifted me from the limitations of living in a remote provincial town – from Zahedan, a rich province with poor people on the margins of Iran – and let me fly.

**Saeed Esmailzaee – Python programmer**

## What OpenFigResolver does

OpenFigResolver automates the search for clean DNS resolvers – servers that correctly resolve both normal domains (e.g., google.com) and domains that are known to be blocked or manipulated (e.g., bbcpersian.com). The script does not bypass censorship itself, but it helps you identify which DNS servers are still behaving correctly.

### Features

- No external packages – uses only the Python standard library.
- Multi‑stage validation:
    - First stage: resolve a trusted domain (e.g., google.com) with configurable retries.
    - Second stage: resolve a domain that is often manipulated (e.g., bbcpersian.com) with a different retry count.
    - Reject resolvers that return a specific blocked IP (e.g., 10.10.10.1).
- Detailed logging – every query result is printed in real time (line‑buffered).
- Output files:
    - `ok.txt` – list of IPs that passed all stages.
    - Detailed report with timing and returned IPs.
    - MikroTik RouterOS script (`*.rsc`) to configure all validated resolvers at once.
- Full configurability – every behaviour can be changed via command‑line arguments or by editing constants at the top of the script.

## Installation

### On Linux / macOS / Windows (with Python 3.6+)

```bash
git clone https://github.com/stableagent/OpenFigResolver.git
cd OpenFigResolver
python availability-tester.py --help
```

To make it available system‑wide on Linux:

```bash
chmod +x availability-tester.py
sudo cp availability-tester.py /usr/local/bin/openfigresolver
```

Now you can run `openfigresolver` from any terminal.

## Usage

### Basic multi‑stage test (what I use daily)

```bash
python availability-tester.py \
    --resolvers resolvers.txt \
    --first-domain google.com --first-retries 3 \
    --second-domain bbcpersian.com --second-retries 5 \
    --blocked-ip 10.10.10.1 \
    --output-ok clean_dns.txt \
    --mikrotik
```

This command:
- Reads resolver IPs from `resolvers.txt` (one IP per line, `#` for comments).
- For each resolver:
    - Tries to resolve `google.com` up to 3 times (stops after first success).
    - If successful, tries to resolve `bbcpersian.com` up to 5 times.
    - If the answer for `bbcpersian.com` is `10.10.10.1` (a typical fake IP used by Iranian ISPs), the resolver is rejected.
- Passed resolvers are saved to `clean_dns.txt` (inside `results/` folder by default).
- A MikroTik script (`validated_dns_*.rsc`) is generated with all passed IPs.

### Other options

| Argument | Description |
|----------|-------------|
| `--resolvers, -r` | File containing resolver IPs (default: `resolvers.txt`) |
| `--timeout, -t` | Timeout per query in seconds (default: `3.0`) |
| `--retry-delay` | Seconds between retries (default: `0.5`) |
| `--output-dir, -o` | Folder to store all result files (default: `results`) |
| `--mikrotik` | Generate a MikroTik address‑list script |
| `--first-domain` | Domain for stage 1 (required) |
| `--first-retries` | Max attempts for stage 1 (default: `3`) |
| `--second-domain` | Domain for stage 2 (required) |
| `--second-retries` | Max attempts for stage 2 (default: `5`) |
| `--blocked-ip` | Reject resolver if stage 2 returns this IP |
| `--output-ok` | File name for the list of passing IPs (default: `ok.txt`) |

## Configuration file (`resolvers.txt`)

Create a plain text file with one IP address per line. Lines starting with `#` are ignored.

Example:

```
# Public DNS
8.8.8.8
1.1.1.1

# Local ISP resolvers (might be manipulated)
10.20.30.1
172.16.0.1
```

## Output files (inside `results/` folder)

- `ok.txt` – List of IPs that passed all stages (one per line).
- `multistage_report_YYYYMMDD_HHMMSS.txt` – Detailed per‑resolver report, including returned IPs and times.
- `validated_dns_YYYYMMDD_HHMMSS_mikrotik.rsc` – MikroTik script with all passed IPs (if `--mikrotik` used).

## Why multi‑stage with blocked IP detection?

In Iran (and similar places), many DNS resolvers:
- Work perfectly for `google.com` (to hide manipulation).
- Return a fake **private IP** (e.g., `10.10.10.1`) for domains that are politically sensitive.

A single‑stage test (e.g., only `google.com`) would mark those manipulated resolvers as “working”. By adding a second domain and blocking the fake IP, `OpenFigResolver` filters out dishonest servers.

## Performance notes

- The script tests resolvers **sequentially** (one after another). This is intentional: it gives clear, debuggable output and does not flood your network.
- Each resolver’s two stages are independent; the script stops as soon as a domain is successfully resolved (first successful response).

## Requirements

- Python 3.6 or higher (no external libraries).
- A network connection – UDP port 53 must be reachable to the resolvers you test.

## Limitations

- IPv4 only (IPv6 resolvers are not tested).
- Uses UDP only – no TCP fallback.
- The DNS parser is simplified; it works for standard A‑record responses but may fail on exotic packets.

## Contributing

Issues and pull requests are welcome. If you live in a country with similar internet restrictions, feel free to share your test domains and blocked IP patterns.

## License

MIT – you are free to use, modify, and distribute.

---

*If you are an Iranian user: this script does not bypass filtering. It only helps you find which DNS servers are still unfiltered.*


