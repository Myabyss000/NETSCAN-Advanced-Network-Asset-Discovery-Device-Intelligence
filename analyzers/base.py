from abc import ABC, abstractmethod

class BaseAnalyzer(ABC):
    def __init__(self, device_manager):
        self.device_manager = device_manager

    @abstractmethod
    def process_packet(self, packet):
        """
        Process a packet and update the device manager if relevant info is found.
        """
        pass
