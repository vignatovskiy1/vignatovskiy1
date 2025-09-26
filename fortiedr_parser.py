import ntpath
import os
import re
import sys
from typing import List, Tuple


def read_input() -> str:
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r', encoding='utf-8') as f:
            return f.read()
    return sys.stdin.read()


def split_events(text: str) -> List[str]:
    parts = text.split('Event GraphAutomated Analysis')
    return [part.strip() for part in parts if part.strip()]


def extract_first_match(pattern: str, text: str, flags: int = 0) -> str:
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else ''


def normalize_process_name(value: str) -> str:
    value = value.strip().strip('"')
    if not value:
        return ''
    # Handle both Windows and POSIX paths
    candidate = ntpath.basename(value)
    candidate = os.path.basename(candidate)
    return candidate or value


def extract_field_from_lines(field: str, lines: List[str]) -> str:
    prefix = f"{field}:"
    for idx, line in enumerate(lines):
        if line.startswith(prefix):
            remainder = line[len(prefix):].strip()
            if remainder:
                return remainder
            if idx + 1 < len(lines):
                next_line = lines[idx + 1].strip()
                if next_line:
                    return next_line
            return ''
    return ''


def parse_user(lines: List[str]) -> str:
    for idx, line in enumerate(lines):
        if line.startswith('User:'):
            remainder = line.partition(':')[2].strip()
            if remainder:
                return remainder
            # If value might be on next line
            if idx + 1 < len(lines):
                next_line = lines[idx + 1].strip()
                if next_line:
                    return next_line
            return ''
    for line in lines:
        if line.startswith('Process Owner:'):
            owner = line.partition(':')[2].strip()
            if owner:
                return owner.split('\\')[-1]
    return ''


def parse_collector_group(lines: List[str]) -> str:
    for idx, line in enumerate(lines):
        if line.strip() == 'Collector groups':
            # scan following lines until non-empty
            for j in range(idx + 1, len(lines)):
                entry = lines[j].strip()
                if not entry or entry == 'All groups':
                    continue
                if entry == 'Default Collector Group':
                    return 'Default'
                return entry
            break
    return ''


def parse_selected_table(lines: List[str]) -> Tuple[str, str, str, str]:
    header_idx = None
    for idx, line in enumerate(lines):
        if 'PROCESS' in line and 'DEVICE' in line and 'CLASSIFICATION' in line:
            header_idx = idx
            break
    if header_idx is None:
        return '', '', '', ''

    # find first non-empty line after header
    for line in lines[header_idx + 1:]:
        data_line = line.strip()
        if not data_line:
            continue
        columns = re.split(r'\s{2,}', data_line)
        if len(columns) >= 3:
            process = columns[0].strip()
            device = columns[1].strip()
            classification = columns[2].strip()
            destination = columns[3].strip() if len(columns) >= 4 else ''
            return process, device, classification, destination
    return '', '', '', ''


def build_output_block(fields: dict) -> str:
    template = (
        "Event ID:                  {EventID}\n"
        "Process:                   {Process}\n"
        "Collector Group:           {CollectorGroup}\n"
        "Device:                    {Device}\n"
        "Logged-in User:            {User}\n"
        "Company:                   {Company}\n"
        "Certification:             {Certification}\n"
        "Classification:            {Classification}\n"
        "Virus Total link:          {VTLink}\n\n"
        "Target: {Target}\n\n"
        "Command Line: {CommandLine}\n\n"
        "Additional information: {AdditionalInfo}\n\n"
        "Tech notes: \n\n"
        "Next Steps:\n"
        "Please advise on actions you would like LNX to take on this FortiEDR event notification. If no response is given, we will mark as Unsafe and BLOCK.\n"
        "-----------------------------------------------------------------------------------------------"
    )
    return template.format(**fields)


def main() -> None:
    raw_text = read_input()
    if not raw_text.strip():
        return

    events = split_events(raw_text)
    outputs = []

    for event in events:
        lines = event.splitlines()

        event_id = extract_first_match(r"Event\s+(\d+)", event)

        table_process, table_device, table_classification, table_destination = parse_selected_table(lines)

        process = ''
        apply_exception = extract_first_match(r"Apply exception on:\s*(.+)", event)
        if apply_exception:
            process = normalize_process_name(apply_exception)
        if not process:
            process = table_process
        if not process:
            process_path = extract_first_match(r"Process Path:\s*(.+)", event)
            if process_path:
                process = normalize_process_name(process_path)

        collector_group = parse_collector_group(lines)

        device = table_device
        if not device:
            device = extract_first_match(r"Device:\s*(.+)", event)

        user = parse_user(lines)

        company = extract_field_from_lines('Company', lines)

        certification_value = extract_field_from_lines('Certificate', lines)
        certification = ''
        if certification_value:
            match = re.search(r"(Signed|Unsigned)", certification_value, re.IGNORECASE)
            if match:
                certification = match.group(1)

        classification = table_classification

        sha1 = extract_first_match(r"Process Hash \(SHA-1\):\s*([0-9a-fA-F]{40})", event)
        vt_link = f"https://www.virustotal.com/gui/search/{sha1}" if sha1 else ''

        target = extract_field_from_lines('Target', lines)

        command_line = extract_field_from_lines('Command Line', lines)

        additional_info = table_destination
        if not additional_info:
            additional_info = extract_first_match(r"([A-Z ]+PHASE)", event)
        if not additional_info:
            for line in lines:
                candidate = line.strip()
                if not candidate or len(candidate) > 60:
                    continue
                if candidate.upper() == candidate and not candidate.startswith('EVENT '):
                    additional_info = candidate
                    break

        fields = {
            'EventID': event_id or 'N/A',
            'Process': process or 'N/A',
            'CollectorGroup': collector_group or 'N/A',
            'Device': device or 'N/A',
            'User': user or 'N/A',
            'Company': company or 'N/A',
            'Certification': certification or 'N/A',
            'Classification': classification or 'N/A',
            'VTLink': vt_link or 'N/A',
            'Target': target or 'N/A',
            'CommandLine': command_line or 'N/A',
            'AdditionalInfo': additional_info or 'N/A',
        }

        outputs.append(build_output_block(fields))

    sys.stdout.write('\n\n'.join(outputs))


if __name__ == '__main__':
    main()
