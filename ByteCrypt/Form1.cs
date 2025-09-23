using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using MaterialSkin;
using MaterialSkin.Controls;

namespace ByteCrypt
{
    public partial class Form1 : MaterialForm
    {
        private MaterialFlatButton btnEncrypt;
        private MaterialFlatButton btnDecrypt;
        private OpenFileDialog openFileDialog;
        private const string password = "YourStrongPassword123!";

        public Form1()
        {
            InitializeComponent();
            InitializeMaterialUI();
        }

        private void InitializeMaterialUI()
        {
            // MaterialSkin manager
            var materialSkinManager = MaterialSkinManager.Instance;
            materialSkinManager.AddFormToManage(this);
            materialSkinManager.Theme = MaterialSkinManager.Themes.DARK;

            // Set custom dark gray theme (32,32,32)
            materialSkinManager.ColorScheme = new ColorScheme(
                Color.FromArgb(32, 32, 32), // Primary
                Color.FromArgb(32, 32, 32), // Dark Primary
                Color.FromArgb(32, 32, 32), // Light Primary
                Color.FromArgb(100, 100, 100), // Accent
                TextShade.WHITE
            );

            this.Text = "ByteCrypt";
            this.Size = new Size(500, 300);

            // Make window not resizable
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = true;

            btnEncrypt = new MaterialFlatButton();
            btnEncrypt.Text = "Encrypt Files";
            btnEncrypt.Location = new Point(50, 100);
            btnEncrypt.Size = new Size(150, 50);
            btnEncrypt.Click += BtnEncrypt_Click;
            this.Controls.Add(btnEncrypt);

            btnDecrypt = new MaterialFlatButton();
            btnDecrypt.Text = "Decrypt Files";
            btnDecrypt.Location = new Point(250, 100);
            btnDecrypt.Size = new Size(150, 50);
            btnDecrypt.Click += BtnDecrypt_Click;
            this.Controls.Add(btnDecrypt);

            openFileDialog = new OpenFileDialog();
            openFileDialog.Multiselect = true; // allow selecting multiple files
        }

        private void BtnEncrypt_Click(object sender, EventArgs e)
        {
            if (openFileDialog.ShowDialog() != DialogResult.OK) return;

            foreach (string filePath in openFileDialog.FileNames)
            {
                string ext = Path.GetExtension(filePath).ToLower();

                try
                {
                    byte[] fileBytes;

                    if (ext == ".png")
                    {
                        using (Bitmap bmp = new Bitmap(filePath))
                        {
                            Bitmap scrambledBmp = ScrambleBitmap(bmp, password);
                            fileBytes = BitmapToBytes(scrambledBmp);
                        }
                    }
                    else
                    {
                        fileBytes = File.ReadAllBytes(filePath);
                    }

                    byte[] encrypted = EncryptFileWithHeader(fileBytes, ext);
                    File.WriteAllBytes(Path.ChangeExtension(filePath, ".byte"), encrypted);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error encrypting {filePath}: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            MessageBox.Show("Selected files encrypted as .byte!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void BtnDecrypt_Click(object sender, EventArgs e)
        {
            openFileDialog.Filter = ".byte files|*.byte|All files|*.*";
            if (openFileDialog.ShowDialog() != DialogResult.OK) return;

            foreach (string filePath in openFileDialog.FileNames)
            {
                try
                {
                    byte[] encrypted = File.ReadAllBytes(filePath);
                    byte[] decrypted = DecryptFileWithHeader(encrypted, out string originalExt);

                    if (originalExt == ".png")
                    {
                        using (Bitmap bmp = BytesToBitmap(decrypted))
                        {
                            Bitmap restored = UnscrambleBitmap(bmp, password);
                            File.WriteAllBytes(Path.ChangeExtension(filePath, "_restored.png"), BitmapToBytes(restored));
                        }
                    }
                    else
                    {
                        File.WriteAllBytes(Path.ChangeExtension(filePath, "_restored" + originalExt), decrypted);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error decrypting {filePath}: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            MessageBox.Show("Selected files decrypted!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // AES encryption/decryption
        private byte[] EncryptBytes(byte[] bytes)
        {
            using (Aes aes = Aes.Create())
            {
                var key = new Rfc2898DeriveBytes(password, new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 });
                aes.Key = key.GetBytes(32);
                aes.IV = key.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytes, 0, bytes.Length);
                    cs.Close();
                    return ms.ToArray();
                }
            }
        }

        private byte[] DecryptBytes(byte[] bytes)
        {
            using (Aes aes = Aes.Create())
            {
                var key = new Rfc2898DeriveBytes(password, new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 });
                aes.Key = key.GetBytes(32);
                aes.IV = key.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytes, 0, bytes.Length);
                    cs.Close();
                    return ms.ToArray();
                }
            }
        }

        // Header methods
        private byte[] EncryptFileWithHeader(byte[] data, string ext)
        {
            byte[] header = new byte[10];
            byte[] extBytes = Encoding.ASCII.GetBytes(ext);
            Array.Copy(extBytes, header, extBytes.Length);

            byte[] combined = new byte[header.Length + data.Length];
            Array.Copy(header, combined, header.Length);
            Array.Copy(data, 0, combined, header.Length, data.Length);

            return EncryptBytes(combined);
        }

        private byte[] DecryptFileWithHeader(byte[] encrypted, out string ext)
        {
            byte[] decrypted = DecryptBytes(encrypted);
            byte[] header = new byte[10];
            Array.Copy(decrypted, header, 10);
            ext = Encoding.ASCII.GetString(header).Trim('\0');

            byte[] fileData = new byte[decrypted.Length - 10];
            Array.Copy(decrypted, 10, fileData, 0, fileData.Length);
            return fileData;
        }

        // Bitmap helpers
        private Bitmap ScrambleBitmap(Bitmap bmp, string password)
        {
            Random rnd = new Random(password.GetHashCode());
            Bitmap newBmp = new Bitmap(bmp.Width, bmp.Height);
            for (int y = 0; y < bmp.Height; y++)
                for (int x = 0; x < bmp.Width; x++)
                {
                    Color c = bmp.GetPixel(x, y);
                    Color newC = Color.FromArgb(c.A,
                        (c.R + rnd.Next(256)) % 256,
                        (c.G + rnd.Next(256)) % 256,
                        (c.B + rnd.Next(256)) % 256);
                    newBmp.SetPixel(x, y, newC);
                }
            return newBmp;
        }

        private Bitmap UnscrambleBitmap(Bitmap bmp, string password)
        {
            Random rnd = new Random(password.GetHashCode());
            Bitmap newBmp = new Bitmap(bmp.Width, bmp.Height);
            for (int y = 0; y < bmp.Height; y++)
                for (int x = 0; x < bmp.Width; x++)
                {
                    Color c = bmp.GetPixel(x, y);
                    Color orig = Color.FromArgb(c.A,
                        (c.R - rnd.Next(256) + 256) % 256,
                        (c.G - rnd.Next(256) + 256) % 256,
                        (c.B - rnd.Next(256) + 256) % 256);
                    newBmp.SetPixel(x, y, orig);
                }
            return newBmp;
        }

        private byte[] BitmapToBytes(Bitmap bmp)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                bmp.Save(ms, ImageFormat.Png);
                return ms.ToArray();
            }
        }

        private Bitmap BytesToBitmap(byte[] bytes)
        {
            using (MemoryStream ms = new MemoryStream(bytes))
            {
                return new Bitmap(ms);
            }
        }
    }
}
