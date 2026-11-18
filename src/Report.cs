using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace TJRemover
{
    static class Report
    {
        static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        public static string Build(IList<Finding> fs, IList<LogEntry> log, string session)
        {
            int threats = fs.Count(f => f.Severity != Severity.Info);
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.Append("<title>Relatório — " + H(Program.AppName) + "</title><style>");
            sb.Append(":root{--bg:#f6f7fb;--card:#fff;--text:#1d2230;--dim:#6b7385;--bd:#e3e6ee;--red:#d93d3d;--org:#d9822b;--grn:#1f9d63;--acc:#3b6fe0}");
            sb.Append("@media(prefers-color-scheme:dark){:root{--bg:#0f1117;--card:#171a23;--text:#e6e8ee;--dim:#8b93a7;--bd:#2c313f;--red:#ff5c5c;--org:#ff9f43;--grn:#3dd68c;--acc:#4c8dff}}");
            sb.Append("body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 'Segoe UI',system-ui,sans-serif}main{max-width:1100px;margin:0 auto;padding:28px 16px}");
            sb.Append("h1{margin:0 0 4px;font-size:26px}h2{margin:32px 0 12px;font-size:18px}.dim{color:var(--dim)}");
            sb.Append(".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px}");
            sb.Append(".card b{display:block;font-size:28px}.verdict{margin-top:18px;padding:14px 18px;border-radius:10px;font-weight:600;background:var(--card);border-left:5px solid var(--grn)}.verdict.bad{border-color:var(--red)}");
            sb.Append(".tbl{overflow-x:auto;background:var(--card);border:1px solid var(--bd);border-radius:10px}table{border-collapse:collapse;width:100%;min-width:720px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--bd);vertical-align:top}");
            sb.Append("th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--dim)}td.path{word-break:break-all}pre{white-space:pre-wrap;margin:6px 0 0;font:12px Consolas,monospace;color:var(--dim)}");
            sb.Append(".s-Crítico{color:var(--red);font-weight:600}.s-Alto{color:var(--org);font-weight:600}.s-Aviso{color:var(--acc)}.ok{color:var(--grn)}.bad{color:var(--red)}");
            sb.Append(".log{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;max-height:480px;overflow:auto}.log pre{color:var(--text)}</style></head><body><main>");

            sb.Append("<h1>Relatório — " + H(Program.AppName) + "</h1>");
            sb.Append("<div class=\"dim\">Computador <b>" + H(Environment.MachineName) + "</b> · gerado em " + DateTime.Now.ToString("dd/MM/yyyy 'às' HH:mm") + "</div>");
            sb.Append(threats > 0
                ? "<div class=\"verdict bad\">" + threats + " ameaça(s) encontrada(s).</div>"
                : "<div class=\"verdict\">Nenhuma ameaça encontrada.</div>");

            Func<FindingKind[], int> cnt = ks => fs.Count(f => ks.Contains(f.Kind));
            sb.Append("<div class=\"cards\">");
            Action<string, int> card = (t, v) => sb.Append("<div class=\"card\"><b>" + v + "</b><span class=\"dim\">" + H(t) + "</span></div>");
            card("Processos ativos", cnt(new[] { FindingKind.Process }));
            card("Arquivos do vírus", cnt(new[] { FindingKind.MaliciousFile }));
            card("Executáveis infectados", cnt(new[] { FindingKind.InfectedFile }));
            card("Inicialização / registro", cnt(new[] { FindingKind.Registry, FindingKind.Autorun }));
            card("Serviços e tarefas", cnt(new[] { FindingKind.Service, FindingKind.Task }));
            card("Avisos", cnt(new[] { FindingKind.Policy }));
            sb.Append("</div>");
            if (!string.IsNullOrEmpty(session))
                sb.Append("<p class=\"dim\">Quarentena e backups da última limpeza: <code>" + H(session) + "</code></p>");

            var recovered = fs.Where(f => f.Kind == FindingKind.InfectedFile && f.Disinfect).ToList();
            if (recovered.Count > 0)
            {
                sb.Append("<h2>Programas desinfetados (original recuperado)</h2><div class=\"tbl\"><table><tr><th>Arquivo</th><th>Família</th><th>Status</th></tr>");
                foreach (var f in recovered) sb.Append("<tr><td class=\"path\">" + H(f.FilePath) + "</td><td>" + H(f.FamilyText) + "</td><td>" + H(f.Status) + "</td></tr>");
                sb.Append("</table></div>");
            }
            var infected = fs.Where(f => f.Kind == FindingKind.InfectedFile && !f.Disinfect).ToList();
            if (infected.Count > 0)
            {
                sb.Append("<h2>Programas infectados (reinstalar)</h2><div class=\"tbl\"><table><tr><th>Arquivo</th><th>Família</th><th>Status</th></tr>");
                foreach (var f in infected) sb.Append("<tr><td class=\"path\">" + H(f.FilePath) + "</td><td>" + H(f.FamilyText) + "</td><td>" + H(f.Status) + "</td></tr>");
                sb.Append("</table></div>");
            }

            sb.Append("<h2>Todos os itens</h2>");
            if (fs.Count == 0) sb.Append("<p class=\"dim\">Nenhum item.</p>");
            else
            {
                sb.Append("<div class=\"tbl\"><table><tr><th>Tipo</th><th>Gravidade</th><th>Item / detalhes</th><th>Status</th></tr>");
                foreach (var f in fs)
                {
                    string cls = f.Failed ? "bad" : f.Done ? "ok" : "";
                    sb.Append("<tr><td>" + H(f.KindText) + "</td><td class=\"s-" + H(f.SeverityText) + "\">" + H(f.SeverityText) + "</td>");
                    sb.Append("<td class=\"path\">" + H(f.Title) + "<pre>" + H(f.Detail) + "</pre></td><td class=\"" + cls + "\">" + H(f.Status) + "</td></tr>");
                }
                sb.Append("</table></div>");
            }

            sb.Append("<h2>Registro de atividades</h2><div class=\"log\"><pre>");
            foreach (var e in log) sb.Append(H(e.Time.ToString("dd/MM HH:mm:ss") + "  " + e.Text) + "\n");
            sb.Append("</pre></div></main></body></html>");
            return sb.ToString();
        }
    }
}
