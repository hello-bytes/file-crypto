package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// 全局变量
	inputFile    string
	outputFile   string
	password     string
	operation    string
	showProgress bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "hellokit-crypt",
		Short: "文件加解密工具",
		Long: `基于AES-CTR算法的文件加解密工具，支持大文件分块处理。
支持加密和解密操作，使用快速MD5算法进行文件完整性验证。`,
	}

	// 加密命令
	var encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "加密文件",
		Long:  `使用AES-CTR算法加密文件`,
		Run: func(cmd *cobra.Command, args []string) {
			if inputFile == "" || outputFile == "" || password == "" {
				fmt.Println("错误: 必须指定输入文件、输出文件和密码")
				cmd.Help()
				os.Exit(1)
			}

			fmt.Printf("开始加密文件: %s -> %s\n", inputFile, outputFile)
			err := EncryptFile(inputFile, outputFile, password, showProgress)
			if err != nil {
				fmt.Printf("加密失败: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("加密完成!")
		},
	}

	// 解密命令
	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "解密文件",
		Long:  `使用AES-CTR算法解密文件`,
		Run: func(cmd *cobra.Command, args []string) {
			if inputFile == "" || outputFile == "" || password == "" {
				fmt.Println("错误: 必须指定输入文件、输出文件和密码")
				cmd.Help()
				os.Exit(1)
			}

			fmt.Printf("开始解密文件: %s -> %s\n", inputFile, outputFile)
			err := DecryptFile(inputFile, outputFile, password, showProgress)
			if err != nil {
				fmt.Printf("解密失败: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("解密完成!")
		},
	}

	// 查看文件信息命令
	var infoCmd = &cobra.Command{
		Use:   "info",
		Short: "查看加密文件信息",
		Long:  `查看加密文件的元数据信息`,
		Run: func(cmd *cobra.Command, args []string) {
			if inputFile == "" {
				fmt.Println("错误: 必须指定输入文件")
				cmd.Help()
				os.Exit(1)
			}

			info, err := GetFileInfo(inputFile)
			if err != nil {
				fmt.Printf("获取文件信息失败: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("文件信息:\n")
			fmt.Printf("  版本: v%d\n", info.Version)
			fmt.Printf("  原始文件名: %s\n", info.FileName)
			fmt.Printf("  原始文件大小: %d bytes (%.2f MB)\n", info.FileSize, float64(info.FileSize)/1024/1024)
			fmt.Printf("  MD5签名: %s\n", info.MD5Sign)
			fmt.Printf("  密码签名: %s\n", info.PasswordSign)
			fmt.Printf("  加密数据块数: %d\n", len(info.BlockSizes))
		},
	}

	// 设置标志
	encryptCmd.Flags().StringVarP(&inputFile, "input", "i", "", "输入文件路径")
	encryptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "输出文件路径")
	encryptCmd.Flags().StringVarP(&password, "password", "p", "", "密码")
	encryptCmd.Flags().BoolVarP(&showProgress, "progress", "v", false, "显示进度")

	decryptCmd.Flags().StringVarP(&inputFile, "input", "i", "", "输入文件路径")
	decryptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "输出文件路径")
	decryptCmd.Flags().StringVarP(&password, "password", "p", "", "密码")
	decryptCmd.Flags().BoolVarP(&showProgress, "progress", "v", false, "显示进度")

	infoCmd.Flags().StringVarP(&inputFile, "input", "i", "", "输入文件路径")

	// 添加命令
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(infoCmd)

	// 执行
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
