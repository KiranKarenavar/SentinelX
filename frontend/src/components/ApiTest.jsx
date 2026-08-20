import { useEffect, useState } from "react";
import API from "../services/api";

function ApiTest() {
    const [status, setStatus] = useState("Checking...");
    const [data, setData] = useState(null);

    useEffect(() => {
        API.get("/")
            .then((response) => {
                setStatus("Backend Connected");
                setData(response.data);
            })
            .catch((error) => {
                console.error(error);
                setStatus("Backend Connection Failed");
            });
    }, []);

    return (
        <div className="dashboard-section">
            <h2>SentinelX Backend</h2>

            <p>{status}</p>

            {data && (
                <pre>
                    {JSON.stringify(data, null, 2)}
                </pre>
            )}
        </div>
    );
}

export default ApiTest;
