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


class LocalStandbyStatus:
    """Local SeekDB node standby status.

    Attributes:
        role (str): Role of the local node, PRIMARY or STANDBY.
        instance_name (str): Instance name of the local SeekDB node.
        log_restore_source (str): Log restore source address (host:rpc_port).
        sync_scn (int or None): The sync SCN of the local node (nanoseconds).
            None if the field is absent in the response.
        readable_scn (int or None): The readable SCN of the local node
            (nanoseconds). None if the field is absent in the response.
        sync_status (str): Sync status. One of NORMAL_SYNC, LOG_ALIGNED,
            SYNC_PAUSED, or empty for PRIMARY.
    """

    def __init__(self, data: dict):
        self.role = data.get("role", "")
        self.instance_name = data.get("instance_name", "")
        self.log_restore_source = data.get("log_restore_source", "")
        self.sync_scn = data.get("sync_scn")
        self.readable_scn = data.get("readable_scn")
        self.sync_status = data.get("sync_status", "")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class PeerStandbyStatus:
    """Status of a remote standby peer.

    Attributes:
        peer_host (str): Peer host address.
        peer_obshell_port (int): Peer obshell port.
        peer_rpc_port (int): Peer SeekDB RPC port.
        direction (str): Direction of this peer, UPSTREAM or DOWNSTREAM.
        role (str): Role of the peer node; empty if unreachable.
        instance_name (str): Instance name of the peer SeekDB node.
        sync_scn (int or None): Peer sync SCN (nanoseconds). None if absent.
        readable_scn (int or None): Peer readable SCN (nanoseconds). None if
            absent.
        lag_seconds (int or None): Replication lag in seconds for DOWNSTREAM
            peers; 0 for UPSTREAM; None if not applicable.
        sync_status (str): Peer sync status; NETWORK_ERROR when unreachable.
        error (str): Error message when the peer is unreachable; empty otherwise.
    """

    def __init__(self, data: dict):
        self.peer_host = data.get("peer_host", "")
        self.peer_obshell_port = data.get("peer_obshell_port", 0)
        self.peer_rpc_port = data.get("peer_rpc_port", 0)
        self.direction = data.get("direction", "")
        self.role = data.get("role", "")
        self.instance_name = data.get("instance_name", "")
        self.sync_scn = data.get("sync_scn")
        self.readable_scn = data.get("readable_scn")
        self.lag_seconds = data.get("lag_seconds")
        self.sync_status = data.get("sync_status", "")
        self.error = data.get("error", "")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class StandbyStatusResp:
    """Response of GET /api/v1/seekdb/standby/status.

    Attributes:
        local (LocalStandbyStatus): Local SeekDB node status.
        peers (list[PeerStandbyStatus]): Status of all configured peers;
            empty list when no peers are configured.
    """

    def __init__(self, data: dict):
        local_data = data.get("local") or {}
        self.local = LocalStandbyStatus(local_data)
        peers_data = data.get("peers") or []
        self.peers = [PeerStandbyStatus(p) for p in peers_data]

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class TokenResp:
    """Response of POST /api/v1/seekdb/standby/token.

    Attributes:
        token (str): The standby token for this node.
    """

    def __init__(self, data: dict):
        self.token = data.get("token", "")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)
