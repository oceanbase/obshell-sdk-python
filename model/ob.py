class UpgradePkgInfo:

    def __init__(self, data: dict):
        self.pkg_id = data.get("pkg_id")
        self.name = data.get("name")
        self.version = data.get("version")
        self.release_distribution = data.get("release_distribution")
        self.distributioin = data.get("distributioin")
        self.architecture = data.get("architecture")
        self.size = data.get("size")
        self.payload_size = data.get("payload_size")
        self.chunk_count = data.get("chunk_count")
        self.md5 = data.get("md5")
        self.upgrade_dep_yaml = data.get("upgrade_dep_yaml")
        self.gmt_modify = data.get("gmt_modify")

    @classmethod
    def from_dict(cls, data: dict):
        return UpgradePkgInfo(data)
