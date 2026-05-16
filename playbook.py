import json
from pydantic import BaseModel


class Meta(BaseModel):
    name: str
    description: str
    version: int
    author: str


class Action(BaseModel):
    scans: list[str]
    files: list[str]
    ftype: str


class Inference(BaseModel):
    wordlist: list[str]
    blacklist: list[str]
    time_deviation: int


class Playbook(BaseModel):
    meta: Meta
    actions: list[Action]
    inference: Inference


def new_playbook(fpath: str) -> Playbook:
    """Load and validate playbook json from disk."""
    with open(fpath, "r", encoding="utf-8") as fp:
        jdata = json.load(fp)
    return Playbook(**jdata)


def NewPlaybook(fpath: str) -> Playbook:
    """Backward-compatible wrapper for legacy callers."""
    return new_playbook(fpath)