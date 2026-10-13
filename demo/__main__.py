import argparse

from demo.server import main

p = argparse.ArgumentParser(description="Local demo app for the security triage agent")
p.add_argument("--port", type=int, default=8765)
main(p.parse_args().port)
