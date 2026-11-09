{% for entries in sections.values() %}
{% for category, definition in definitions.items() if category in entries %}
{% if category == 'other' %}
<details>
<summary>{{ definition.name }}</summary>
{% else %}
### {{ definition.name }}
{% endif %}

{% for text, issues in entries[category].items() %}
{% set reference_separator = "\n\n  " if "\n" in text else " " %}
- {{ text.rstrip() }}{{ reference_separator ~ issues|join(", ") if issues else "" }}
{% endfor %}
{% if category == 'other' %}

</details>
{% endif %}

{% endfor %}
{% endfor %}
