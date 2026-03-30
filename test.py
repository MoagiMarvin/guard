from agents.db_guard import db_guard_agent

if __name__ == "__main__":
    test_query = "SELECT * FROM users WHERE username = 'admin' OR 1=1; --"
    print(f"Testing with Gemini 2.5 Flash!")
    print(f"Query: {test_query}\n")
    try:
        result = db_guard_agent(test_query)
        print("Response from AI Guardian:")
        for key, value in result.items():
            print(f"- {key}: {value}")
    except Exception as e:
        print(f"An error occurred: {e}")
