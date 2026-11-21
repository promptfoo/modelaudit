{% for entries in sections.values() %}
{% for category, definition in definitions.items() if category in entries %}
### {{ definition.name }}

{% for text, issues in entries[category].items() %}
{% set reference_separator = "\n\n  " if "\n" in text else " " %}
- {{ text.rstrip() }}{{ reference_separator ~ issues|join(", ") if issues else "" }}
{% endfor %}

{% endfor %}
{% endfor %}
