export default function SingleVersionNotice({ message }) {
  return (
    <div
      style={{
        padding: "16px 20px",
        borderRadius: 8,
        background: "#FFF8E1",
        border: "1px solid #FFE082",
        color: "#8A6D00",
        fontSize: 14,
      }}
    >
      {message ||
        "Une seule version disponible. Le comparatif s'activera au prochain réentraînement du modèle."}
    </div>
  );
}