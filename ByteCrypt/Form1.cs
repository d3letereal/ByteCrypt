using System;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using MetroFramework;
using MetroFramework.Forms;

namespace ByteCrypt
{
    public partial class Form1 : MetroForm
    {
        private MetroFramework.Controls.MetroButton btnEncrypt;
        private MetroFramework.Controls.MetroButton btnDecrypt;
        private Label lblTitle;
        private Label lblSubTitle;
        private Label lblKey;
        private MetroFramework.Controls.MetroTextBox txtKey;
        private OpenFileDialog openFileDialog;

        public Form1()
        {
            InitializeComponent();
            InitializeUI();
        }

        private void InitializeUI()
        {
            // Form settings
            this.Text = "ByteCrypt";
            this.Size = new Size(520, 400);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MaximizeBox = false;
            this.MinimizeBox = true;
            this.Style = MetroColorStyle.Blue;
            this.Theme = MetroThemeStyle.Dark;
            this.BackColor = Color.FromArgb(30, 30, 30); // Dark background

            // Title label
            lblTitle = new Label
            {
                Text = "ByteCrypt",
                Location = new Point(0, 20),
                Size = new Size(this.ClientSize.Width, 40),
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 18, FontStyle.Bold),
                ForeColor = Color.White,
              //  BackColor = Color.FromArgb(30, 30, 30)
            };
            this.Controls.Add(lblTitle);

            // Subtitle label
            lblSubTitle = new Label
            {
                Text = "Encrypt or decrypt your files securely",
                Location = new Point(0, 65),
                Size = new Size(this.ClientSize.Width, 25),
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 10, FontStyle.Regular),
                ForeColor = Color.LightGray,
               // BackColor = Color.FromArgb(30, 30, 30)
            };
            this.Controls.Add(lblSubTitle);

            // Key label
            lblKey = new Label
            {
                Text = "Encryption Key:",
                Location = new Point(40, 110),
                Size = new Size(440, 25),
                Font = new Font("Segoe UI", 10, FontStyle.Regular),
                ForeColor = Color.White,
               // BackColor = Color.FromArgb(30, 30, 30)
            };
            this.Controls.Add(lblKey);

            // Key textbox
            txtKey = new MetroFramework.Controls.MetroTextBox
            {
                Location = new Point(40, 140),
                Size = new Size(440, 30),
                WaterMark = "Default: BYTEISSUPERCUTE!",
                ShowClearButton = true,
                AutoCompleteMode = AutoCompleteMode.None,
                AutoCompleteSource = AutoCompleteSource.None,
                UseCustomBackColor = true,
                BackColor = Color.FromArgb(45, 45, 45),
                UseCustomForeColor = true,
                ForeColor = Color.White,
                WaterMarkColor = Color.Gray,
                WaterMarkFont = new Font("Segoe UI", 9F, FontStyle.Italic)
            };
            txtKey.CustomButton.Visible = false;
            this.Controls.Add(txtKey);

            // Encrypt button
            btnEncrypt = new MetroFramework.Controls.MetroButton
            {
                Text = "Encrypt Files",
                Location = new Point(60, 200),
                Size = new Size(180, 50),
                UseSelectable = true,
                BackColor = Color.FromArgb(30, 30, 30)
            };
            btnEncrypt.Click += BtnEncrypt_Click;
            this.Controls.Add(btnEncrypt);

            // Decrypt button
            btnDecrypt = new MetroFramework.Controls.MetroButton
            {
                Text = "Decrypt Files",
                Location = new Point(280, 200),
                Size = new Size(180, 50),
                UseSelectable = true,
                BackColor = Color.FromArgb(30, 30, 30)
            };
            btnDecrypt.Click += BtnDecrypt_Click;
            this.Controls.Add(btnDecrypt);

            // File dialog
            openFileDialog = new OpenFileDialog
            {
                Multiselect = true,
                Title = "Select files to encrypt/decrypt"
            };
        }

        private string GetKey()
        {
            string key = txtKey.Text;
            return string.IsNullOrEmpty(key) ? "BYTEISSUPERCUTE!" : key;
        }

        private void BtnEncrypt_Click(object sender, EventArgs e)
        {
            if (openFileDialog.ShowDialog() != DialogResult.OK) return;

            string password = GetKey();

            foreach (string filePath in openFileDialog.FileNames)
            {
                string ext = Path.GetExtension(filePath).ToLower();

                try
                {
                    byte[] fileBytes = File.ReadAllBytes(filePath);
                    byte[] encrypted = EncryptFileWithHeader(fileBytes, ext, password);
                    File.WriteAllBytes(Path.ChangeExtension(filePath, ".byte"), encrypted);
                }
                catch (Exception ex)
                {
                    MetroMessageBox.Show(this, $"Error encrypting {filePath}: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            MetroMessageBox.Show(this, "Selected files encrypted as .byte!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void BtnDecrypt_Click(object sender, EventArgs e)
        {
            if (openFileDialog.ShowDialog() != DialogResult.OK) return;

            string password = GetKey();

            foreach (string filePath in openFileDialog.FileNames)
            {
                try
                {
                    byte[] encrypted = File.ReadAllBytes(filePath);
                    byte[] decrypted = DecryptFileWithHeader(encrypted, out string originalExt, password);
                    File.WriteAllBytes(Path.ChangeExtension(filePath, "_restored" + originalExt), decrypted);
                }
                catch (Exception ex)
                {
                    MetroMessageBox.Show(this, $"Error decrypting {filePath}: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            MetroMessageBox.Show(this, "Selected files decrypted!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private byte[] EncryptBytes(byte[] bytes, string password)
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

        private byte[] DecryptBytes(byte[] bytes, string password)
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

        private byte[] EncryptFileWithHeader(byte[] data, string ext, string password)
        {
            byte[] header = new byte[10];
            byte[] extBytes = Encoding.ASCII.GetBytes(ext);
            Array.Copy(extBytes, header, extBytes.Length);

            byte[] combined = new byte[header.Length + data.Length];
            Array.Copy(header, combined, header.Length);
            Array.Copy(data, 0, combined, header.Length, data.Length);

            return EncryptBytes(combined, password);
        }

        private byte[] DecryptFileWithHeader(byte[] encrypted, out string ext, string password)
        {
            byte[] decrypted = DecryptBytes(encrypted, password);
            byte[] header = new byte[10];
            Array.Copy(decrypted, header, 10);
            ext = Encoding.ASCII.GetString(header).Trim('\0');

            byte[] fileData = new byte[decrypted.Length - 10];
            Array.Copy(decrypted, 10, fileData, 0, fileData.Length);
            return fileData;
        }
    }
}
