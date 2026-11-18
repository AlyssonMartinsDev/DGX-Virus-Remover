using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace TJRemover
{
    static class C
    {
        public static readonly Color Bg = Color.FromArgb(15, 17, 23);
        public static readonly Color Panel = Color.FromArgb(23, 26, 35);
        public static readonly Color Card = Color.FromArgb(31, 35, 47);
        public static readonly Color Border = Color.FromArgb(44, 49, 63);
        public static readonly Color Text = Color.FromArgb(230, 232, 238);
        public static readonly Color Dim = Color.FromArgb(139, 147, 167);
        public static readonly Color Accent = Color.FromArgb(0x25, 0x83, 0xFF);
        public static readonly Color Accent2 = Color.FromArgb(0x5A, 0xA7, 0xFF);
        public static readonly Color Red = Color.FromArgb(255, 92, 92);
        public static readonly Color Orange = Color.FromArgb(255, 159, 67);
        public static readonly Color Yellow = Color.FromArgb(245, 196, 81);
        public static readonly Color Green = Color.FromArgb(61, 214, 140);

        public static GraphicsPath Round(RectangleF r, float rad)
        {
            var p = new GraphicsPath();
            float d = Math.Min(rad * 2, Math.Min(r.Width, r.Height));
            if (d <= 0.5f) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }
    }

    /// <summary>Barra de progresso plana com gradiente e brilho animado.</summary>
    class FlatBar : Control
    {
        double value, shimmer;
        public bool Busy;
        public Color From = C.Accent, To = C.Accent2;

        public FlatBar()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                     ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
            BackColor = C.Bg;
        }

        public double Value
        {
            get { return value; }
            set { double v = Math.Max(0, Math.Min(1, value)); if (Math.Abs(v - this.value) > 0.0005) { this.value = v; Invalidate(); } }
        }

        public void Animate()
        {
            if (!Busy) return;
            shimmer += 0.025;
            if (shimmer > 1.6) shimmer = -0.4;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(BackColor);
            var track = new RectangleF(0, 0, Width - 1, Height - 1);
            float rad = Height / 2f;
            using (var p = C.Round(track, rad))
            using (var b = new SolidBrush(C.Card))
                g.FillPath(b, p);
            float w = (float)(track.Width * value);
            if (w < 2) return;
            var fill = new RectangleF(0, 0, Math.Max(w, Height), track.Height);
            using (var p = C.Round(fill, rad))
            {
                using (var b = new LinearGradientBrush(new RectangleF(0, 0, track.Width, track.Height), From, To, 0f))
                    g.FillPath(b, p);
                if (Busy)
                {
                    float cx = (float)(shimmer * fill.Width);
                    var hl = new RectangleF(cx - 60, 0, 120, fill.Height);
                    using (var hb = new LinearGradientBrush(hl, Color.FromArgb(0, Color.White), Color.FromArgb(0, Color.White), 0f))
                    {
                        var blend = new ColorBlend
                        {
                            Positions = new[] { 0f, 0.5f, 1f },
                            Colors = new[] { Color.FromArgb(0, Color.White), Color.FromArgb(70, Color.White), Color.FromArgb(0, Color.White) }
                        };
                        hb.InterpolationColors = blend;
                        var old = g.Clip;
                        g.SetClip(p);
                        g.FillRectangle(hb, hl);
                        g.Clip = old;
                    }
                }
            }
        }
    }

    /// <summary>Cartão com um número grande e uma legenda.</summary>
    class StatCard : Panel
    {
        readonly Label num, cap;
        readonly Color accent;
        int value;

        public StatCard(string caption, Color accent)
        {
            this.accent = accent;
            BackColor = C.Card;
            DoubleBuffered = true;
            Padding = new Padding(16, 6, 8, 6);
            num = new Label { Dock = DockStyle.Top, Height = 42, Font = new Font("Segoe UI Semibold", 21f), ForeColor = C.Dim, Text = "0", TextAlign = ContentAlignment.MiddleLeft };
            cap = new Label { Dock = DockStyle.Top, Height = 22, Font = new Font("Segoe UI", 9f), ForeColor = C.Dim, Text = caption, AutoEllipsis = true };
            Controls.Add(cap);
            Controls.Add(num);
        }

        public void SetValue(int v)
        {
            if (v == value && num.Text == v.ToString()) return;
            value = v;
            num.Text = v.ToString();
            num.ForeColor = v > 0 ? accent : C.Dim;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            using (var b = new SolidBrush(value > 0 ? accent : C.Border))
                e.Graphics.FillRectangle(b, 0, 0, 4, Height);
        }
    }

    /// <summary>Logo DGX Virus Remover: bloco azul-marinho, círculo com X ao fundo, "DGX" + "virus remover".</summary>
    class DgxLogo : Control
    {
        public DgxLogo()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        }

        static readonly Color Blue1 = Color.FromArgb(0x5A, 0xA7, 0xFF), Blue2 = Color.FromArgb(0x25, 0x83, 0xFF);
        static readonly Color Light = Color.FromArgb(0x71, 0xB1, 0xFF), White = Color.FromArgb(0xF8, 0xFA, 0xFC);

        static GraphicsPath RoundRect(RectangleF r, float rad)
        {
            var p = new GraphicsPath(); float d = rad * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90); p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure(); return p;
        }

        /// <summary>Desenha a marca. Abaixo de 48 px só o círculo com X; a partir de 48 px o "DGX"; a partir de 96 px o subtítulo.</summary>
        public static void Draw(Graphics g, RectangleF r)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
            float s = Math.Min(r.Width, r.Height), x = r.X, y = r.Y;
            var tile = new RectangleF(x, y, s, s);
            bool text = s >= 44, sub = s >= 90;

            using (var path = RoundRect(tile, s * 0.2f))
            {
                using (var b = new LinearGradientBrush(tile, Color.FromArgb(0x10, 0x2C, 0x53), Color.FromArgb(0x05, 0x10, 0x20), 45f))
                    g.FillPath(b, path);
                using (var pen = new Pen(Blue2, Math.Max(1f, s * 0.016f)))
                    g.DrawPath(pen, path);
            }

            // círculo com X (ao fundo quando há texto; em destaque nos tamanhos pequenos)
            float cr = sub ? s * 0.31f : text ? s * 0.36f : s * 0.33f;
            float cx = x + s / 2f, cy = y + (sub ? s * 0.42f : s / 2f);
            int alpha = text ? 110 : 255;
            var circ = new RectangleF(cx - cr, cy - cr, cr * 2, cr * 2);
            float sw = Math.Max(1.6f, s * (text ? 0.075f : 0.11f));
            using (var gb = new LinearGradientBrush(circ, Color.FromArgb(alpha, Blue1), Color.FromArgb(alpha, Blue2), 45f))
            using (var pen = new Pen(gb, sw) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                if (text)
                    for (int i = 3; i >= 1; i--)   // brilho suave
                        using (var glow = new Pen(Color.FromArgb(18, Blue2), sw + s * 0.03f * i))
                            g.DrawEllipse(glow, circ);
                g.DrawEllipse(pen, circ);
                float k = cr * 0.45f;
                g.DrawLine(pen, cx - k, cy - k, cx + k, cy + k);
                g.DrawLine(pen, cx + k, cy - k, cx - k, cy + k);
            }
            if (!text) return;

            // "DGX"
            using (var f = new Font("Segoe UI", s * 0.25f, FontStyle.Bold, GraphicsUnit.Pixel))
            using (var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            {
                var tr = new RectangleF(x, cy - s * 0.18f, s, s * 0.36f);
                using (var sh = new SolidBrush(Color.FromArgb(200, 2, 8, 18)))
                    g.DrawString("DGX", f, sh, new RectangleF(tr.X + s * 0.012f, tr.Y + s * 0.016f, tr.Width, tr.Height), sf);
                using (var wb = new SolidBrush(White))
                    g.DrawString("DGX", f, wb, tr, sf);
            }
            if (!sub) return;
            using (var f = new Font("Segoe UI Semibold", s * 0.105f, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            using (var lb = new SolidBrush(Light))
                g.DrawString("virus remover", f, lb, new RectangleF(x, y + s * 0.76f, s, s * 0.14f), sf);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(Parent != null ? Parent.BackColor : C.Panel);
            int s = Math.Min(Width, Height) - 2;
            Draw(e.Graphics, new RectangleF((Width - s) / 2f, (Height - s) / 2f, s, s));
        }
    }
}
