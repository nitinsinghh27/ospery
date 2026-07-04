{#
  Use the custom +schema name as-is (e.g. "silver", "gold") instead of dbt's
  default "<target_schema>_<custom>". Keeps clean medallion schema names.
#}
{% macro generate_schema_name(custom_schema_name, node) -%}
    {%- if custom_schema_name is none -%}
        {{ target.schema }}
    {%- else -%}
        {{ custom_schema_name | trim }}
    {%- endif -%}
{%- endmacro %}
