console.log("Hello from the frontend!");

// Test function to call the backend API and log the result
export async function testBackendApi() {
    try {
        const response = await fetch("http://localhost:3000/api/recipes");
        if (!response.ok) {
            throw new Error(`API call failed with status ${response.status}`);
        }
        const data = await response.json();
        console.log("Backend API test passed. Data:", data);
    } catch (err) {
        console.error("Backend API test failed:", err);
    }
}

// Example usage
testBackendApi();