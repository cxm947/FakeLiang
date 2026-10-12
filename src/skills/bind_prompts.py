"""Static system prompt for card selection."""
from agents._prompt_resources import read_prompt

SYSTEM = read_prompt(__package__, "templates/bind_system.txt")
