using System;
using System.Runtime.InteropServices;
using System.Text;

public sealed class BreakawayCreation {
  public bool Created;
  public int ErrorCode;
}

public static class BreakawayProbe {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
  private static extern bool CreateProcessW(string application, StringBuilder command,
    IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags,
    IntPtr environment, string directory, IntPtr startup, IntPtr information);

  public static BreakawayCreation Create(string application, StringBuilder command,
    uint flags, string directory, IntPtr startup, IntPtr information) {
    bool created = CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero,
      false, flags, IntPtr.Zero, directory, startup, information);
    int error = Marshal.GetLastWin32Error();
    return new BreakawayCreation { Created = created, ErrorCode = error };
  }
}
