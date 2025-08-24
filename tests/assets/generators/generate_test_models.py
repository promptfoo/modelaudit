#!/usr/bin/env python
"""Generate test models for our test suite"""

from pathlib import Path

from create_steganographic_attack import create_simple_malicious_pickle, create_steganographic_attack


def main():
    # Create output directory
    assets_dir = Path(__file__).parent.parent / "pickles"
    assets_dir.mkdir(exist_ok=True)

    # Generate steganographic attack model
    steg_path = assets_dir / "steganographic_attack.pkl"
    simple_path = assets_dir / "simple_eval_attack.pkl"

    print("🏭 Generating test models...")

    # Create steganographic attack
    _, stream1_size, stream2_size = create_steganographic_attack(str(steg_path))
    print(f"✅ Created: {steg_path}")

    # Create simple attack
    create_simple_malicious_pickle(str(simple_path))
    print(f"✅ Created: {simple_path}")

    print("\n📁 Test Models Generated:")
    print(f"   - steganographic_attack.pkl ({stream1_size + stream2_size} bytes, 2 streams)")
    print("   - simple_eval_attack.pkl (single stream)")


if __name__ == "__main__":
    main()
