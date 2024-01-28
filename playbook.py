from pydantic import BaseModel
from typing import List
import json

class Meta(BaseModel):
    name: str
    description: str
    version: int
    author: str

class Action(BaseModel):
    scans: List[str]
    files: List[str]
    ftype: str

class Inference(BaseModel):
    wordlist: List[str]
    blacklist: List[str]
    time_deviation: int

class Playbook(BaseModel):
    meta: Meta
    actions: List[Action]
    inference: Inference


def NewPlaybook(fpath) -> Playbook:
    fp = open(fpath)
    jdata = json.load(fp)
    fp.close()
    return Playbook(**jdata)