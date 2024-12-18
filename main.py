
from obshell import initialize_nodes, start_obshell, check_nodes, NodeConfig
from obshell import ClientSet


def init_nodes():
    pkgs = [
        "/root/download/oceanbase-ce-libs-4.2.5.0-100000052024102022.el7.x86_64.rpm",
        "/root/download/oceanbase-ce-4.2.5.0-100000052024102022.el7.x86_64.rpm",
        # 这里使用的 OB 4.2.5.0 版本中已经包含了 obshell，但推荐使用最新版本的 obshell，所以这里单独安装了最新版本的 obshell
        "/root/download/obshell-4.2.4.3-12024110711.el7.x86_64.rpm",
    ]

    ips = [
        "10.10.21.90",
        "10.10.21.91",
        "10.10.21.92",
    ]
    work_dir = "/data/ob" # OBServer 的工作目录，不需要提前创建，初始化 OBServer 时会自动创建
    nodes_config = []
    for _, ip in enumerate(ips):
        node = NodeConfig(ip, work_dir)
        nodes_config.append(node)

    # # sdk 会自动判断是否使用 rsync，如果不想使用 rsync，传输效率比较低
    # # 使用 rsync 传输文件时，需要在 SDK 执行机器和目标机器之间配置免密登录，同时两边都需要安装 rsync.
    # # 你可以通过以下方法关闭 rsync 传输，但是不推荐这么做
    # from obshell.ssh import USE_RSYNC
    # USE_RSYNC = False

    # 初始化节点
    # 参数说明：
    # rpm_packages: 所需要安装的软件包路径
    # force_clean: 是否强制清理 OBServer 工作目录，如果为 True，则工作目录会被清空并 kill 掉所有相关进程
    # configs: 集群配置项, 必须是 NodeConfig 类型的列表
    initialize_nodes(rpm_packages=pkgs, force_clean=True, configs=nodes_config)

    # 启动 obshell
    start_obshell(nodes_config)


def create_cluster():
    ips = [
        "10.10.21.90",
        "10.10.21.91",
        "10.10.21.92",
    ]
    work_dir = "/data/ob" # OBServer 的工作目录，不需要提前创建，初始化 OBServer 时会自动创建

    # 创建 sdk 客户端
    client = ClientSet(ips[0])

    # 填充各节点的配置
    configs = {}
    i = 0
    for ip in ips:
        i += 1
        configs["%s:2886" % ip] = {
            "zone": "zone%s" % (i % 3 + 1), # 打散到三个 zone
            "home_path": work_dir,
            # "data_dir": data_dir, # 数据目录
            # "redo_dir": redo_dir, # 日志目录
            "datafile_size": "14G", "cpu_count": "6",
            "memory_limit": "16G", "system_memory": "4G", "log_disk_size": "14G",
            "enable_syslog_recycle": "true", "enable_syslog_wf": "true","__min_full_resource_pool_memory": "1073741824"
        }

    # 创建集群
    client.v1.agg_create_cluster(
        configs,
        "cluster-obtest", # 集群名
        1, # 集群ID
        "Password-0BTest" # root@sys 密码
        # clear_if_failed=True # 执行失败会清理环境
    )

if __name__ == '__main__':
    # client.v1.agg_clear_uninitialized_agent() # 手动清理环境
    # init_nodes()
    # create_cluster()
    ips = [
        "10.10.21.90",
        "10.10.21.91",
        "10.10.21.92",
    ]
    work_dir = "/data/ob" # OBServer 的工作目录，不需要提前创建，初始化 OBServer 时会自动创建
    nodes_config = []
    for _, ip in enumerate(ips):
        node = NodeConfig(ip, work_dir, username='admin', password='Admin091!')
        # node = NodeConfig(ip, work_dir)
        nodes_config.append(node)
    errors, warns = check_nodes(nodes_config)
    if errors:
        for error in errors:
            print("message:{} suggest:{}".format(error.message, error.suggest))
    if warns:
        for warn in warns:
            print("message:{} suggest:{}".format(warn.message, warn.suggest))