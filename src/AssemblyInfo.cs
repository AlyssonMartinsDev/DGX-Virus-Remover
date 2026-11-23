using System.Reflection;
using System.Runtime.InteropServices;

// Aparece em Propriedades > Detalhes do .exe.
// Ao lançar uma versão nova, atualize os números aqui e crie a tag correspondente (ex.: v1.0.0).
[assembly: AssemblyTitle("DGX Virus Remover")]
// ATENÇÃO: não escreva aqui o nome exato do vírus "TJ…Main" — o texto vai para dentro do .exe e o programa
// passaria a detectar a si mesmo. Use "Mofksys". (O build do GitHub falha se isso acontecer.)
[assembly: AssemblyDescription("Remoção e desinfecção de Mofksys, Synaptics, Grenam e Sality, com quarentena e proteção.")]
[assembly: AssemblyCompany("DGX")]
[assembly: AssemblyProduct("DGX Virus Remover")]
[assembly: AssemblyCopyright("© 2026 DGX")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyInformationalVersion("1.0.0")]
[assembly: ComVisible(false)]
