
class Client:

    def __init__(self, host: str, port:int = 2886, **kwargs) -> None:
        """
        Initialize a new Client instance.

        Args:
            host (str): The hostname or IP address of the server to connect to.
            port (int, optional): The port number of the server. Defaults to 2886.
        """
        self.host = host
        self.port = port
        self.task_queue = []
        self.is_syncing = False

    