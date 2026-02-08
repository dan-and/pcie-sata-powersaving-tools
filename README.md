# pcie-sata-powersaving-tools
A bundle of PCI(e), Sata and Linux Powersaving tools

## pcie_error-monitor.py
A Python script that monitors PCI devices for Advanced Error Reporting (AER) status changes in real-time.

### Usage
```bash
sudo python3 pcie_error-monitor.py [-v] [poll_interval_seconds]
```
- Requires root privileges (or equivalent) to read AER status via `lspci`.
- `poll_interval_seconds`: Time in seconds between checks (default: 1.0).
- `-v` or `--verbose`: Enable verbose output.
