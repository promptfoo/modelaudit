#!/usr/bin/env python
"""Generate V4 test models for ultimate evasion testing"""

from pathlib import Path

from create_steganographic_attack_v4 import create_ultimate_steganographic_attack, create_verification_model


def main():
    # Create output directory
    assets_dir = Path(__file__).parent.parent / "pickles"
    assets_dir.mkdir(exist_ok=True)

    # Generate V4 ultimate steganographic attack model
    v4_path = assets_dir / "steganographic_attack_v4.pkl"
    innocent_v4_path = assets_dir / "innocent_model_v4.pkl"

    print("🏭 Generating V4 test models...")

    # Create V4 ultimate evasion attack
    _, v4_size = create_ultimate_steganographic_attack(str(v4_path))
    print(f"✅ Created: {v4_path}")

    # Create innocent model for comparison
    create_verification_model(str(innocent_v4_path))
    print(f"✅ Created: {innocent_v4_path}")

    print("\n📁 V4 Test Models Generated:")
    print(f"   - steganographic_attack_v4.pkl ({v4_size} bytes, single stream, embedded payload)")
    print("   - innocent_model_v4.pkl (truly innocent model for comparison)")


if __name__ == "__main__":
    main()
