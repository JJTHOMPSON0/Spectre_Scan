"""
Timing Templates Module
Implements Nmap-style timing templates (-T0 through -T5)
"""

class TimingProfile:
    """Defines timing and performance characteristics for different scan speeds"""
    
    def __init__(self, level, name, description):
        self.level = level
        self.name = name
        self.description = description
        self.timeout = self.get_timeout()
        self.concurrency = self.get_concurrency()
        self.retry_limit = self.get_retry_limit()
        self.packet_delay = self.get_packet_delay()
    
    def get_timeout(self):
        """Get timeout in seconds based on timing level"""
        timeouts = {
            0: 300,    # Paranoid: 5 minutes
            1: 60,     # Sneaky: 1 minute
            2: 5.0,    # Polite: 5 seconds
            3: 1.0,    # Normal: 1 second (default)
            4: 0.5,    # Aggressive: 500ms
            5: 0.1,    # Insane: 100ms
        }
        return timeouts.get(self.level, 1.0)
    
    def get_concurrency(self):
        """Get max concurrent probes"""
        concurrency = {
            0: 1,      # Paranoid: 1 probe at a time
            1: 2,      # Sneaky: 2 probes
            2: 50,     # Polite: 50 probes
            3: 500,    # Normal: 500 probes (default)
            4: 1000,   # Aggressive: 1000 probes
            5: 2000,   # Insane: 2000 probes
        }
        return concurrency.get(self.level, 500)
    
    def get_retry_limit(self):
        """Get max retry attempts"""
        retries = {
            0: 10,     # Paranoid: 10 retries
            1: 5,      # Sneaky: 5 retries
            2: 3,      # Polite: 3 retries
            3: 2,      # Normal: 2 retries (default)
            4: 1,      # Aggressive: 1 retry
            5: 0,      # Insane: no retries
        }
        return retries.get(self.level, 2)
    
    def get_packet_delay(self):
        """Get delay between packets in milliseconds"""
        delays = {
            0: 300000,  # Paranoid: 300ms delay
            1: 100000,  # Sneaky: 100ms delay
            2: 10000,   # Polite: 10ms delay
            3: 0,       # Normal: no delay (default)
            4: 0,       # Aggressive: no delay
            5: 0,       # Insane: no delay
        }
        return delays.get(self.level, 0) / 1000.0
    
    def __repr__(self):
        return f"T{self.level} ({self.name}): {self.description}"


# Timing profiles
TIMING_PROFILES = {
    0: TimingProfile(0, "Paranoid", "Very slow and stealthy, for IDS evasion"),
    1: TimingProfile(1, "Sneaky", "Slow, stealthy, lower detection risk"),
    2: TimingProfile(2, "Polite", "Reduced load, network-friendly"),
    3: TimingProfile(3, "Normal", "Default timing, balanced"),
    4: TimingProfile(4, "Aggressive", "Fast scanning, higher network load"),
    5: TimingProfile(5, "Insane", "Very fast, may overwhelm network"),
}


def get_timing_profile(level):
    """Get a timing profile by level (0-5)"""
    level = min(5, max(0, level))  # Clamp to 0-5
    return TIMING_PROFILES[level]


def describe_timing_profile(level):
    """Get description of timing profile"""
    profile = get_timing_profile(level)
    return (
        f"T{level}: {profile.name}\n"
        f"  Description: {profile.description}\n"
        f"  Timeout: {profile.timeout}s\n"
        f"  Concurrency: {profile.concurrency} probes\n"
        f"  Retries: {profile.retry_limit}\n"
        f"  Packet delay: {profile.packet_delay*1000:.0f}ms"
    )
