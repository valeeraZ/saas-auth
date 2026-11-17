from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictBool

RoleKey = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]


class RoleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: RoleKey
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    active: StrictBool = True
