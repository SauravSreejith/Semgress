from locust import HttpUser, task, between

class SemgressLoadTest(HttpUser):
    wait_time = between(0.1, 0.5)

    @task(3)
    def test_fast_path(self):
        """Bypasses ML entirely (<5ms)."""
        self.client.get("/get", name="Fast Path GET")

    @task(1)
    def test_cached_malicious_attack(self):
        """
        Expects HTTP 403 from WAF. 
        catch_response=True tells Locust that 403 is a SUCCESS, not a failure.
        """
        with self.client.get(
            "/get?q=admin'%20OR%201=1--", 
            name="SQLi Attack (Expect 403)", 
            catch_response=True
        ) as response:
            if response.status_code == 403:
                response.success()
            else:
                response.failure(f"WAF failed to block! Status: {response.status_code}")

    @task(1)
    def test_deep_inspection(self):
        """Dynamic payload forcing GPU batch inference."""
        import random
        query_val = random.randint(1000, 9999)
        self.client.post(
            "/post", 
            json={"user_input": f"Hello, my query ID is {query_val}"},
            name="Dynamic Deep Inspection"
        )