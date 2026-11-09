{% for entries in sections.values() %}
{% for category, definition in definitions.items() if category in entries %}
{% if category == 'other' %}
<details>
<summary>{{ definition.name }}</summary>
{% else %}
### {{ definition.name }}
{% endif %}

{% for text, issues in entries[category].items() %}
- {{ text }}{{ " " ~ issues|join(", ") if issues else "" }}
{% endfor %}
{% if category == 'other' %}

</details>
{% endif %}

{% endfor %}
{% endfor %}
