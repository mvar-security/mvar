"""
Test S1501-02: Mission Control adapter type import path fix.

Verifies that the adapter can be imported and initialized.
"""
import asyncio


def test_mission_control_adapter_import_and_init():
    """Verify adapter imports and can be initialized."""
    from mvar.mission_control.adapter import MVARAdapter

    async def run_test():
        adapter = MVARAdapter(api_key="k", qseal_secret="s")
        await adapter.close()

    asyncio.run(run_test())
