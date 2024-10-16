# coding: utf-8
# Copyright (c) 2024 OceanBase.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from enum import Enum
from .format import model_str


class State(Enum):
    PENDING_STR = "PENDING"
    READY_STR = "READY"
    RUNNING_STR = "RUNNING"
    FAILED_STR = "FAILED"
    SUCCEED_STR = "SUCCEED"


class Operator(Enum):
    RUN_STR = "RUN"
    RETRY_STR = "RETRY"
    ROLLBACK_STR = "ROLLBACK"
    CANCEL_STR = "CANCEL"
    PASS_STR = "PASS"


class TaskStatusDTO:

    def __init__(self, data: dict):
        self.state = data["state"]
        self.operator = data["operator"]
        self.start_time = data["start_time"]
        self.end_time = data["end_time"]

    @classmethod
    def from_dict(cls, data: dict):
        return TaskStatusDTO(data)

    def is_succeed(self) -> bool:
        return self.state == State.SUCCEED_STR.value

    def is_failed(self) -> bool:
        return self.state == State.FAILED_STR.value

    def is_running(self) -> bool:
        return self.state == State.RUNNING_STR.value

    def is_finished(self) -> bool:
        return (self.state == State.SUCCEED_STR.value or
                self.state == State.FAILED_STR.value)

    def is_run(self) -> bool:
        return self.operator == Operator.RUN_STR.value

    def is_rollback(self) -> bool:
        return self.operator == Operator.ROLLBACK_STR.value

    def is_retry(self) -> bool:
        return self.operator == Operator.RETRY_STR.value

    def is_cancel(self) -> bool:
        return self.operator == Operator.CANCEL_STR.value

    def __str__(self) -> str:
        return model_str(self)


class DagDetailDTO(TaskStatusDTO):

    def __init__(self, data: json):
        super().__init__(data)
        self.generic_id = data.get("id")
        self.dag_id = data.get("dag_id")
        self.name = data.get("name")
        self.stage = data.get("stage")
        self.max_stage = data.get("max_stage")
        nodes = data.get("nodes")
        self.nodes = ([NodeDetailDTO.from_dict(node) for node in nodes]
                      if nodes is not None else [])
        self.additional_data = data.get("additional_data")

    @classmethod
    def from_dict(cls, data: dict):
        return DagDetailDTO(data)

    def __str__(self) -> str:
        return model_str(self)


class NodeDetailDTO(TaskStatusDTO):

    def __init__(self, data: dict):
        super().__init__(data)
        self.generic_id = data.get("id")
        self.node_id = data.get("node_id")
        self.name = data.get("name")
        sub_tasks = data.get("sub_tasks")
        self.sub_tasks = ([TaskDetailDTO.from_dict(task) for task in sub_tasks]
                          if sub_tasks is not None else [])
        self.additional_data = data.get("additional_data"),

    @classmethod
    def from_dict(cls, data: dict):
        return NodeDetailDTO(data)

    def __str__(self) -> str:
        return model_str(self)


class TaskDetailDTO(TaskStatusDTO):

    def __init__(self, data: dict):
        super().__init__(data)
        self.generic_id = data.get("id")
        self.task_id = data.get("task_id")
        self.name = data.get("name")
        self.execute_times = data.get("execute_times")
        self.execute_agent = (f"{data.get('execute_agent').get('ip')}:"
                              f"{data.get('execute_agent').get('port')}")
        self.task_logs = data.get("task_logs")
        self.additional_data = data.get("additional_data")

    @classmethod
    def from_dict(cls, data: dict):
        return TaskDetailDTO(data)

    def __str__(self) -> str:
        return model_str(self)
