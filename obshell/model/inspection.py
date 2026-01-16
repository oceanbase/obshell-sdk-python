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

from .format import model_str


class InspectionReport:
    """Inspection report model for storing cluster inspection results.

    Attributes:
        id (int): Inspection report ID.
        local_task_id (str): Local task ID for the inspection.
        scenario (str): Inspection scenario, e.g., "basic" or "performance".
        status (str): Inspection status.
        start_time (str): Start time of the inspection.
        finish_time (str): Finish time of the inspection.
        error_message (str): Error message if inspection failed.
        pass_count (int): Number of passed inspection items.
        failed_count (int): Number of failed inspection items.
        warning_count (int): Number of warning inspection items.
        critical_count (int): Number of critical inspection items.
        result_detail (ResultDetail): Detailed results of the inspection.
    """

    def __init__(self, data: dict):
        self.id = data.get("id")
        self.local_task_id = data.get("local_task_id")
        self.scenario = data.get("scenario")
        self.status = data.get("status")
        self.start_time = data.get("start_time")
        self.finish_time = data.get("finish_time")
        self.error_message = data.get("error_message")
        self.pass_count = data.get("pass_count")
        self.failed_count = data.get("failed_count")
        self.warning_count = data.get("warning_count")
        self.critical_count = data.get("critical_count")
        result_detail_data = data.get("result_detail")
        self.result_detail = ResultDetail(result_detail_data) if result_detail_data else None

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class InspectionReportBriefInfo:
    """Brief inspection report info model for listing inspection history.

    Attributes:
        id (int): Inspection report ID.
        local_task_id (str): Local task ID for the inspection.
        scenario (str): Inspection scenario, e.g., "basic" or "performance".
        status (str): Inspection status.
        start_time (str): Start time of the inspection.
        finish_time (str): Finish time of the inspection.
        error_message (str): Error message if inspection failed.
        pass_count (int): Number of passed inspection items.
        failed_count (int): Number of failed inspection items.
        warning_count (int): Number of warning inspection items.
        critical_count (int): Number of critical inspection items.
    """

    def __init__(self, data: dict):
        self.id = data.get("id")
        self.local_task_id = data.get("local_task_id")
        self.scenario = data.get("scenario")
        self.status = data.get("status")
        self.start_time = data.get("start_time")
        self.finish_time = data.get("finish_time")
        self.error_message = data.get("error_message")
        self.pass_count = data.get("pass_count")
        self.failed_count = data.get("failed_count")
        self.warning_count = data.get("warning_count")
        self.critical_count = data.get("critical_count")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class InspectionItem:
    """Inspection item model for storing individual inspection results.

    Attributes:
        name (str): Name of the inspection item.
        results (list): List of result messages for the inspection item.
    """

    def __init__(self, data: dict):
        self.name = data.get("name")
        self.results = data.get("results", [])

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class ResultDetail:
    """Result detail model for storing categorized inspection results.

    Attributes:
        pass_items (list): List of InspectionItem objects that passed.
        failed_items (list): List of InspectionItem objects that failed.
        warning_items (list): List of InspectionItem objects that have warnings.
        critical_items (list): List of InspectionItem objects that are critical.
    """

    def __init__(self, data: dict):
        pass_items_data = data.get("pass_items")
        self.pass_items = [InspectionItem(item) for item in pass_items_data] if pass_items_data else []
        failed_items_data = data.get("failed_items")
        self.failed_items = [InspectionItem(item) for item in failed_items_data] if failed_items_data else []
        warning_items_data = data.get("warning_items")
        self.warning_items = [InspectionItem(item) for item in warning_items_data] if warning_items_data else []
        critical_items_data = data.get("critical_items")
        self.critical_items = [InspectionItem(item) for item in critical_items_data] if critical_items_data else []

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class PaginatedInspectionHistoryResponse:
    """Paginated inspection history response model.

    Attributes:
        contents (list): List of InspectionReportBriefInfo objects.
        page (CustomPage): Pagination information.
    """

    def __init__(self, data: dict):
        contents_data = data.get("contents")
        self.contents = [InspectionReportBriefInfo(c) for c in contents_data] if contents_data else []
        page_data = data.get("page")
        self.page = CustomPage(page_data) if page_data else None

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class CustomPage:
    """Custom page model for pagination.

    Attributes:
        number (int): Current page number.
        size (int): Page size.
        total_pages (int): Total number of pages.
        total_elements (int): Total number of elements.
    """

    def __init__(self, data: dict):
        self.number = data.get("number")
        self.size = data.get("size")
        self.total_pages = data.get("total_pages")
        self.total_elements = data.get("total_elements")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)