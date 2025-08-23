#!/usr/bin/env python3
"""
Simple Changelog Section Sorter

Sorts entries within sections by PR number in descending order (highest first).
Also groups by conventional commit type for better organization.
"""

import re


def extract_pr_number(line):
    """Extract PR number from a changelog entry line."""
    match = re.search(r'#(\d+)', line)
    return int(match.group(1)) if match else 0


def extract_commit_type(line):
    """Extract conventional commit type from a changelog entry line."""
    match = re.search(r'\*\*(\w+)\*\*:', line)
    return match.group(1) if match else "unknown"


def sort_changelog_section(lines):
    """Sort lines in a changelog section."""
    entries = []
    non_entries = []
    
    for line in lines:
        if line.strip().startswith('- **') and '**:' in line:
            entries.append(line)
        else:
            non_entries.append(line)
    
    # Sort by type priority first, then by PR number descending
    type_priority = {
        'feat': 1, 'docs': 2, 'test': 3, 'ci': 4,
        'perf': 5, 'chore': 6, 'refactor': 7, 'style': 8,
        'fix': 9, 'security': 10
    }
    
    def sort_key(line):
        commit_type = extract_commit_type(line)
        pr_number = extract_pr_number(line)
        priority = type_priority.get(commit_type, 999)
        return (priority, -pr_number)  # Negative PR number for descending order
    
    entries.sort(key=sort_key)
    
    return entries + non_entries


def process_changelog():
    """Process the changelog file."""
    with open('CHANGELOG.md', 'r') as f:
        lines = f.readlines()
    
    result = []
    current_section_lines = []
    in_section = False
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        if re.match(r'^### (Added|Changed|Fixed|Security|Removed)', line.strip()):
            # Sort previous section if we were in one
            if in_section and current_section_lines:
                sorted_section = sort_changelog_section(current_section_lines)
                result.extend(sorted_section)
            
            # Start new section
            result.append(line)
            current_section_lines = []
            in_section = True
            
        elif re.match(r'^(###|##|\[)', line.strip()) or i == len(lines) - 1:
            # End of current section
            if in_section and current_section_lines:
                sorted_section = sort_changelog_section(current_section_lines)
                result.extend(sorted_section)
            
            if i == len(lines) - 1 and not re.match(r'^(###|##|\[)', line.strip()):
                result.append(line)
            elif re.match(r'^(###|##|\[)', line.strip()):
                result.append(line)
            
            current_section_lines = []
            in_section = False
            
        elif in_section:
            current_section_lines.append(line)
        else:
            result.append(line)
        
        i += 1
    
    # Write result
    with open('CHANGELOG.md', 'w') as f:
        f.writelines(result)
    
    print("✅ Changelog sections sorted successfully!")


if __name__ == "__main__":
    process_changelog()