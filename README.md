# ECU Offensive Simulation Framework

A security testing framework for automotive Electronic Control Units (ECUs) via UDS/DoIP protocols. Built for penetration testers and security engineers working on automotive cybersecurity assessments in compliance with ISO 21434.

## Architecture

```
+---------------------------------------------------------------+
|                        CLI Interface                          |
|  record | replay | fuzz | analyze | report                    |
+---------------------------------------------------------------+
|                      Attack Modules                           |
|  +----------+ +--------+ +-----------+ +------------------+  |
|  |  Replay  | | Fuzzer | | Negative  | | SecurityAccess   |  |
|  |  Attack  | |        | | Testing   | | Analysis         |  |
|  +----------+ +--------+ +-----------+ +------------------+  |
+---------------------------------------------------------------+
|                     Protocol Layer                            |
|  +--------+   +--------+   +--------------------+            |
|  |  UDS   |   |  DoIP  |   |  CAN Interface     |            |
|  | (0x10, |   | (TCP/  |   |  (python-can)      |            |
|  |  0x27, |   |  13400)|   |                    |            |
|  |  0x31) |   +--------+   +--------------------+            |
|  +--------+                                                   |
+---------------------------------------------------------------+
|                    Reporting Engine                            |
|  ISO 21434 Reports | CVSS Scoring | Risk Matrix              |
+---------------------------------------------------------------+
|                    Configuration                              |
|  ECU Profiles (YAML) | Attack Configs | Logging              |
+---------------------------------------------------------------+
```

## Supported Attack Types

| Attack Type        | Description                                              |
|--------------------|----------------------------------------------------------|
| Replay Attack      | Capture and replay UDS diagnostic sessions               |
| Fuzzing            | Random, sequential, and smart payload generation         |
| Negative Testing   | Out-of-range DIDs, invalid transitions, oversized data   |
| SecurityAccess     | Seed entropy analysis, key derivation, brute force       |

## Protocols

### UDS (Unified Diagnostic Services) - ISO 14229

Supported service IDs:

| SID  | Service                    | Purpose                          |
|------|----------------------------|----------------------------------|
| 0x10 | DiagnosticSessionControl   | Switch diagnostic sessions       |
| 0x11 | ECUReset                   | Reset the ECU                    |
| 0x22 | ReadDataByIdentifier       | Read DID values                  |
| 0x27 | SecurityAccess             | Seed-key authentication          |
| 0x2E | WriteDataByIdentifier      | Write DID values                 |
| 0x31 | RoutineControl             | Execute routines                 |
| 0x34 | RequestDownload            | Initiate download                |
| 0x36 | TransferData               | Transfer firmware data           |
| 0x37 | RequestTransferExit        | End data transfer                |
| 0x3E | TesterPresent              | Keep session alive               |

### DoIP (Diagnostics over IP) - ISO 13400

- Vehicle identification request/response
- Diagnostic message routing
- TCP connection management on port 13400

### CAN Bus

- Configurable bus speed (125k, 250k, 500k, 1M baud)
- Supports SocketCAN, PCAN, Vector interfaces
- Traffic recording and deterministic playback

## Setup

```bash
# Clone the repository
git clone https://github.com/jalal-essmail/ecu-offensive-simulation.git
cd ecu-offensive-simulation

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Record CAN/UDS Traffic

```bash
# Record traffic from CAN interface
python cli.py record --interface vcan0 --duration 60 --output captures/session.pcap

# Record with specific arbitration ID filter
python cli.py record --interface vcan0 --arb-id 0x7E0 --duration 30
```

### Replay Captured Traffic

```bash
# Replay a captured session
python cli.py replay --capture captures/session.pcap --interface vcan0

# Replay with timing analysis
python cli.py replay --capture captures/session.pcap --interface vcan0 --preserve-timing
```

### Fuzz ECU Services

```bash
# Random fuzzing of SecurityAccess service
python cli.py fuzz --target 0x7E0 --service 0x27 --strategy random --iterations 10000

# Smart fuzzing with boundary values
python cli.py fuzz --target 0x7E0 --service 0x22 --strategy smart --config configs/attack_configs/fuzz_config.yaml
```

### Analyze Security Access

```bash
# Collect and analyze seeds
python cli.py analyze --target 0x7E0 --mode seed-entropy --samples 1000

# Test for seed reuse
python cli.py analyze --target 0x7E0 --mode seed-reuse --samples 500
```

### Generate Report

```bash
# Generate ISO 21434 compliant report
python cli.py report --input results/ --format markdown --output report.md

# Generate JSON report with CVSS scores
python cli.py report --input results/ --format json --output report.json
```

## ECU Profiles

ECU profiles define target-specific parameters. See `configs/ecu_profiles/generic_ecu.yaml` for the template.

```yaml
ecu:
  name: "Target ECU"
  can_id_tx: 0x7E0
  can_id_rx: 0x7E8
  supported_sessions:
    - default
    - programming
    - extended
```

## ISO 21434 Compliance

This framework supports the threat analysis and risk assessment (TARA) process defined in ISO 21434:

- **Clause 8**: Cybersecurity risk assessment through automated attack simulation
- **Clause 9**: Verification of cybersecurity goals via negative testing
- **Clause 15**: Vulnerability analysis through fuzzing and SecurityAccess testing

Reports generated by this tool map findings to ISO 21434 clauses and include CVSS v3.1 base scores adapted for automotive context.

## Disclaimer

This tool is intended for **authorized security testing only**. Use it exclusively on ECUs and systems you have explicit permission to test. Unauthorized access to vehicle systems is illegal in most jurisdictions. The author assumes no liability for misuse of this software.

Always:
- Obtain written authorization before testing
- Work in isolated lab environments
- Follow your organization's responsible disclosure policy
- Comply with applicable laws and regulations

## License

MIT License - see [LICENSE](LICENSE)

## Author

J. Essmail
