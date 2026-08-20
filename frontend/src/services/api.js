import axios from "axios";

const API_BASE_URL = "http://127.0.0.1:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json",
  },
});

export const getDashboardSummary = async () => {
  const response = await api.get("/dashboard/summary");
  return response.data;
};

export const getIncidents = async () => {
  const response = await api.get("/incidents");
  return response.data;
};

export const getHuntingQueries = async () => {
  const response = await api.get("/hunting/queries");
  return response.data;
};

export const getAIHealth = async () => {
  const response = await api.get("/ai/health");
  return response.data;
};

export default api;
