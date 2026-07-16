# Walkthrough: AADS gRPC-over-UDS Client & Tests

We have implemented the client interface and mock verification tests for AADS communication with the Go Control Plane.

---

## 🛠️ Work Done

1. **Protobuf Compilation**:
   Compiled `kb.proto` from the control plane (`kb-control-plane/proto/kb.proto`) to generate the Python protobuf and gRPC interfaces:
   - [kb_pb2.py](file:///home/emergence/Desktop/kernel-borderlands/kb-aads/comms/kb_pb2.py)
   - [kb_pb2_grpc.py](file:///home/emergence/Desktop/kernel-borderlands/kb-aads/comms/kb_pb2_grpc.py)

2. **gRPC Client Implementation**:
   Fleshed out the gRPC client in [grpc_client.py](file:///home/emergence/Desktop/kernel-borderlands/kb-aads/comms/grpc_client.py) with methods mapping to all RPC services:
   - `get_process_state(pid)`
   - `list_zone(zone)`
   - `set_containment(pid, level, reason)`
   - `stream_events(event_types)`
   - `stream_alerts(event_types)`
   - `submit_decision(decision_id, agent_id, pid, action, confidence, authorized_by)`

3. **UDS Integration Tests**:
   Created a test file [test_grpc_client.py](file:///home/emergence/Desktop/kernel-borderlands/kb-aads/tests/test_grpc_client.py) which:
   - Starts a mock gRPC server inside a ThreadPoolExecutor.
   - Binds to a local Unix Domain Socket file in the tests directory (`test-kba.sock`).
   - Asserts correct serialization, transmission, and deserialization for all gRPC endpoints.

---

## 🧪 Validation & Test Results

We verified the client by running `pytest` in the virtual environment. All 6 tests passed successfully:

```bash
source venv/bin/activate
pytest tests/
```

### Output:
```text
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/emergence/Desktop/kernel-borderlands/kb-aads
plugins: asyncio-1.4.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collecting ... collected 6 items                                                              

tests/test_grpc_client.py ......                                         [100%]

============================== 6 passed in 0.15s ===============================
```
