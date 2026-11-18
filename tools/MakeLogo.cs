// Gera assets\DGX Virus Remover.ico e PNGs a partir de DgxLogo.Draw (compilado junto com src\Controls.cs).
using System; using System.Drawing; using System.Drawing.Imaging; using System.IO; using System.Collections.Generic;
class MakeLogo {
  static Bitmap Render(int s) {
    var bmp = new Bitmap(s, s, PixelFormat.Format32bppArgb);
    using (var g = Graphics.FromImage(bmp)) { g.Clear(Color.Transparent); float pad = s >= 48 ? s * 0.02f : 0.5f; TJRemover.DgxLogo.Draw(g, new RectangleF(pad, pad, s - 2*pad - 1, s - 2*pad - 1)); }
    return bmp; }
  static void Main(string[] a) {
    string dir = a[0];
    int[] sizes = {16,24,32,48,64,128,256}; var pngs = new List<byte[]>();
    foreach (int s in sizes) using (var bmp = Render(s)) using (var ms = new MemoryStream()) { bmp.Save(ms, ImageFormat.Png); pngs.Add(ms.ToArray()); }
    foreach (int s in new[]{128,256,512}) using (var bmp = Render(s)) bmp.Save(Path.Combine(dir, "icon_" + s + ".png"), ImageFormat.Png);
    if (a.Length > 1) { using (var sheet = new Bitmap(220, 70)) using (var g = Graphics.FromImage(sheet)) { g.Clear(Color.FromArgb(23,26,35)); int xx = 4; foreach (int s in new[]{16,24,32,48,64}) { using (var b = Render(s)) g.DrawImage(b, xx, 3); xx += s + 8; } sheet.Save(a[1], ImageFormat.Png); } }
    using (var fs = new FileStream(Path.Combine(dir, "DGX Virus Remover.ico"), FileMode.Create)) using (var w = new BinaryWriter(fs)) {
      w.Write((short)0); w.Write((short)1); w.Write((short)sizes.Length); int off = 6 + 16 * sizes.Length;
      for (int i = 0; i < sizes.Length; i++) { byte d = (byte)(sizes[i] >= 256 ? 0 : sizes[i]); w.Write(d); w.Write(d); w.Write((byte)0); w.Write((byte)0); w.Write((short)1); w.Write((short)32); w.Write(pngs[i].Length); w.Write(off); off += pngs[i].Length; }
      foreach (var p in pngs) w.Write(p); } } }

