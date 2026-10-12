"""The planner's two distinct system prompts, read without normalization."""
from agents._prompt_resources import read_prompt

WALK_SYSTEM = read_prompt(__package__, "templates/walk_system.txt")
IO_SYSTEM = read_prompt(__package__, "templates/io_system.txt")
