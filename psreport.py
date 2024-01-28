from pydantic import BaseModel
from typing import List

class DLLEntry(BaseModel):
    dll_path:str
    dll_name:str
    load_time:str

class Relation(BaseModel):
    proc_path:str
    proc_name:str
    confidence:int
    actual_deviation:int
    create_time:str
    evi:str
    pid:str
    dll:List[DLLEntry]

class PSMatch(BaseModel):
    fpath:str
    access_time:str
    allowed_deviation:int
    evi:str
    relations:List[Relation]