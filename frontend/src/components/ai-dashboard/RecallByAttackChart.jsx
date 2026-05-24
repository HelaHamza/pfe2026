import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, ReferenceLine, Cell,
} from "recharts"

const COLORS = ["#85B7EB", "#1565C0", "#E65100", "#6A1B9A"]
const SEUIL = 0.5

export default function RecallByAttackChart({ byAttack, versions }) {
  // byAttack = comparison.by_attack : { attaque: [ {version, value (recall), detected, total} ] }
  if (!byAttack || !versions || versions.length === 0) return null

  // Format Recharts : une ligne par attaque, une colonne par version
  const data = Object.entries(byAttack).map(([attack, series]) => {
    const row = { attack }
    series.forEach((point) => {
      row[point.version] = point.value   // value = recall
    })
    return row
  })

  return (
    <div style={{ width: "100%", height: 400 }}>
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 70 }}>
          <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
          <XAxis dataKey="attack" angle={-35} textAnchor="end" interval={0} height={90} fontSize={12} />
          <YAxis domain={[0, 1]} fontSize={12} />
          <Tooltip />
          <Legend />
          <ReferenceLine y={SEUIL} stroke="#C62828" strokeDasharray="4 4"
            label={{ value: "seuil 0.50", position: "right", fontSize: 11, fill: "#C62828" }} />
          {versions.map((v, vi) => (
            <Bar key={v} dataKey={v} fill={COLORS[vi % COLORS.length]}>
              {data.map((d, di) => (
                <Cell key={di} fill={d[v] < SEUIL ? "#E24B4A" : COLORS[vi % COLORS.length]} />
              ))}
            </Bar>
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}