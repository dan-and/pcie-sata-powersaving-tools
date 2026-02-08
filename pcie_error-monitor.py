#!/usr/bin/env python3
import subprocess
import re
import sys
import time
from datetime import datetime
from itertools import groupby
from collections import defaultdict

ERROR_EXPLANATIONS = {
    'DLP': 'Data Link Protocol error',
    'SDES': 'Surprise Down Error Status',
    'TLP': 'Transaction Layer Packet error',
    'FCP': 'Flow Control Protocol error',
    'CmpltTO': 'Completion Timeout',
    'CmpltAbrt': 'Completion Abort',
    'UnxCmplt': 'Unexpected Completion',
    'RxOF': 'Receiver Overflow',
    'MalfTLP': 'Malformed TLP',
    'ECRC': 'ECRC error',
    'UnsupReq': 'Unsupported Request',
    'ACSViol': 'ACS Violation',
    'RxErr': 'Receiver Error',
    'BadTLP': 'Bad TLP',
    'BadDLLP': 'Bad DLLP',
    'Rollover': 'Rollover error',
    'Timeout': 'Timeout error',
    'AdvNonFatalErr': 'Advanced Non-Fatal Error',
}

def parse_aer_field(field_str):
    """Parse UESta or CESta field string into set of active flags."""
    flags = set()
    if not field_str:
        return flags
    
    parts = field_str.split()
    for part in parts:
        if part.endswith('+'):
            flags.add(part[:-1])
    return flags

def scan_pci_devices():
    """Scan all PCI devices and extract AER status."""
    try:
        result = subprocess.run(['lspci', '-vv'], capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError:
        return {}
    except FileNotFoundError:
        print("Error: lspci not found. Please install pciutils.")
        return {}

    devices = {}
    current_device = None
    
    for line in result.stdout.splitlines():
        # Match both "0000:00:00.0" (domain:bus:slot.func) and "00:00.0" (bus:slot.func)
        device_match = re.match(r'^((?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9])', line)
        if device_match:
            current_device = device_match.group(1)
            name = line[device_match.end():].strip()
            devices[current_device] = {'UESta': set(), 'CESta': set(), 'name': name}
        elif current_device and 'Advanced Error Reporting' in line:
            in_aer = True
        elif current_device and line.strip().startswith('UESta:'):
            field_match = re.search(r'UESta:\s*(.+)', line)
            if field_match:
                devices[current_device]['UESta'] = parse_aer_field(field_match.group(1))
        elif current_device and line.strip().startswith('CESta:'):
            field_match = re.search(r'CESta:\s*(.+)', line)
            if field_match:
                devices[current_device]['CESta'] = parse_aer_field(field_match.group(1))
    
    return devices

def compare_states(previous, current):
    """Compare previous and current states, return newly detected errors."""
    changes = []
    
    for device in current:
        if device not in previous:
            previous[device] = {'UESta': set(), 'CESta': set()}
        
        for field in ['UESta', 'CESta']:
            new_flags = current[device][field] - previous[device][field]
            if new_flags:
                changes.append({
                    'device': device,
                    'field': field,
                    'flags': new_flags,
                    'name': current[device].get('name', ''),
                })
    
    return changes

def format_error_message(change, verbose: bool = False):
    """Format error message for a detected change."""
    device = change['device']
    field = change['field']
    flags = change['flags']
    name = change.get('name', '')
    
    flag_strs = [f"{flag}+" for flag in sorted(flags)]
    explanations = [ERROR_EXPLANATIONS.get(flag, flag) or flag for flag in sorted(flags)]
    
    timestamp = datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
    flags_part = ' '.join(flag_strs)
    explanations_part = ', '.join(explanations)
    
    error_line = f"{timestamp} Device {device} {field} {flags_part} : {explanations_part}"
    if verbose and name:
        name_line = f"{timestamp} Device {device} {name}"
        return f"{name_line}\n{error_line}"
    return error_line

def monitor_devices(poll_interval: float = 1.0, verbose: bool = False):
    """Monitor PCI devices for AER changes."""
    print("PCIe AER Monitor started. Press Ctrl+C to stop.")
    
    previous_state = {}
    
    try:
        while True:
            current_state = scan_pci_devices()
            if not current_state:
                print("Error: No PCI devices found. Is lspci available?", file=sys.stderr)
                sys.exit(1)
            any_aer = any(
                current_state[d]['UESta'] or current_state[d]['CESta']
                for d in current_state
            )
            if not any_aer:
                print(
                    "Error: No UESta/CESta data found. "
                    "Run as root (or with equivalent privileges) to read AER status.",
                    file=sys.stderr,
                )
                sys.exit(1)
            changes = compare_states(previous_state, current_state)
            
            if verbose:
                for device, device_changes in groupby(
                    sorted(changes, key=lambda c: c['device']), key=lambda c: c['device']
                ):
                    device_changes = list(device_changes)
                    first = device_changes[0]
                    if first.get('name'):
                        timestamp = datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
                        print(f"{timestamp} Device {first['device']} {first['name']}")
                    for change in device_changes:
                        print(format_error_message(change, verbose=False))
            else:
                for change in changes:
                    print(format_error_message(change, verbose=False))
            
            previous_state = current_state
            time.sleep(poll_interval)
    
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if a != '-v' and a != '--verbose']
    verbose = '-v' in sys.argv or '--verbose' in sys.argv
    poll_interval = 1
    if args:
        try:
            poll_interval = float(args[0])
        except ValueError:
            print(f"Invalid poll interval: {args[0]}")
            print("Usage: python3 aer_monitor.py [-v] [poll_interval_seconds]")
            sys.exit(1)
    
    monitor_devices(poll_interval, verbose=verbose)
