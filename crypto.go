package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

const (
	CHUNK_SIZE = 2 * 1024 * 1024   // 2MB chunks
	FRONT_SIZE = 100 * 1024 * 1024 // 100MB
	TAIL_SIZE  = 10 * 1024 * 1024  // 10MB
	MIN_SIZE   = 20 * 1024 * 1024  // 20MB
)

// FileInfo 文件信息结构
type FileInfo struct {
	Version       int    `json:"version"`
	MD5Sign       string `json:"md5Sign"`
	FileName      string `json:"name"`
	FileSize      int64  `json:"size"`
	PasswordSign  string `json:"ps"`
	BlockSizes    []int  `json:"fb"`
	EncryptedSize int64  `json:"encryptedSize"`
}

// 计算快速MD5（前100MB + 后10MB + 文件大小）
func calculateRapidFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return "", err
	}

	fileSize := stat.Size()
	hash := md5.New()

	// 如果文件小于20MB，计算整个文件的MD5
	if fileSize <= MIN_SIZE {
		_, err = io.Copy(hash, file)
		if err != nil {
			return "", err
		}
	} else {
		// 读取前100MB
		offset := int64(0)
		for offset < FRONT_SIZE && offset < fileSize {
			chunkSize := CHUNK_SIZE
			if offset+int64(chunkSize) > FRONT_SIZE {
				chunkSize = int(FRONT_SIZE - offset)
			}
			if offset+int64(chunkSize) > fileSize {
				chunkSize = int(fileSize - offset)
			}

			chunk := make([]byte, chunkSize)
			_, err = file.ReadAt(chunk, offset)
			if err != nil {
				return "", err
			}
			hash.Write(chunk)
			offset += int64(chunkSize)
		}

		// 读取尾部10MB
		if fileSize > FRONT_SIZE {
			tailStart := int64(FRONT_SIZE)
			if fileSize-TAIL_SIZE > FRONT_SIZE {
				tailStart = fileSize - TAIL_SIZE
			}

			offset = tailStart
			for offset < fileSize {
				chunkSize := CHUNK_SIZE
				if offset+int64(chunkSize) > fileSize {
					chunkSize = int(fileSize - offset)
				}

				chunk := make([]byte, chunkSize)
				_, err = file.ReadAt(chunk, offset)
				if err != nil {
					return "", err
				}
				hash.Write(chunk)
				offset += int64(chunkSize)
			}
		}

		// 添加文件大小信息到MD5计算中
		hash.Write([]byte(fmt.Sprintf("%d", fileSize)))
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// 计算完整文件MD5
func calculateFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// 生成密钥和IV
func generateKeyAndIV(password string) ([]byte, []byte, error) {
	key := []byte(password)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		// 如果长度不足16字节，用0填充到16字节
		if len(key) < 16 {
			paddedKey := make([]byte, 16)
			copy(paddedKey, key)
			key = paddedKey
		} else if len(key) < 24 {
			// 如果长度在16-24之间，填充到24字节
			paddedKey := make([]byte, 24)
			copy(paddedKey, key)
			key = paddedKey
		} else if len(key) < 32 {
			// 如果长度在24-32之间，填充到32字节
			paddedKey := make([]byte, 32)
			copy(paddedKey, key)
			key = paddedKey
		} else {
			// 如果长度超过32字节，截取前32字节
			key = key[:32]
		}
	}

	h1 := sha1.Sum(key)
	h1Hex := hex.EncodeToString(h1[:])

	h2 := sha1.Sum([]byte(h1Hex))
	h2Hex := hex.EncodeToString(h2[:])

	h3 := sha1.Sum([]byte(h2Hex))
	h3Hex := hex.EncodeToString(h3[:])

	ivHex := h3Hex[:16]
	if len(ivHex) < 16 {
		ivHex = ivHex + strings.Repeat("0", 16-len(ivHex))
	}
	iv := []byte(ivHex)
	if len(iv) != 16 {
		paddedIV := make([]byte, 16)
		copy(paddedIV, iv)
		if len(iv) < 16 {
			for i := len(iv); i < 16; i++ {
				paddedIV[i] = 0
			}
		}
		iv = paddedIV
	}

	return key, iv, nil
}

// 生成密码签名
func generatePasswordSign(password string) string {
	h1 := sha1.Sum([]byte(password))
	h1Hex := hex.EncodeToString(h1[:])

	// 使用Keccak-512，与JavaScript的CryptoJS.SHA3一致
	h2 := sha3.NewLegacyKeccak512()
	h2.Write([]byte(h1Hex))
	h2Hex := hex.EncodeToString(h2.Sum(nil))

	h3 := sha3.NewLegacyKeccak512()
	h3.Write([]byte(h2Hex))
	h3Hex := hex.EncodeToString(h3.Sum(nil))

	// 返回前12个字符
	return h3Hex[:12]
}

// 加密文件
func EncryptFile(inputPath, outputPath, password string, showProgress bool) error {
	// 计算文件MD5
	fileMD5, err := calculateRapidFileMD5(inputPath)
	if err != nil {
		return fmt.Errorf("计算文件MD5失败: %v", err)
	}
	md5Sign := fileMD5[:12]

	// 生成密钥和IV
	key, iv, err := generateKeyAndIV(password)
	if err != nil {
		return fmt.Errorf("生成密钥失败: %v", err)
	}

	// 打开输入文件
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %v", err)
	}
	defer inputFile.Close()

	// 获取文件信息
	stat, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %v", err)
	}
	fileSize := stat.Size()

	// 创建输出文件
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outputFile.Close()

	// 创建文件头
	header := fmt.Sprintf("[hkef][%s][v3]", md5Sign)
	_, err = outputFile.WriteString(header)
	if err != nil {
		return fmt.Errorf("写入文件头失败: %v", err)
	}

	// 创建AES-CTR加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("创建AES加密器失败: %v", err)
	}
	stream := cipher.NewCTR(block, iv)

	// 分块加密
	var fileBlocks []int
	offset := int64(0)
	totalChunks := (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE
	currentChunk := int64(0)

	for offset < fileSize {
		blockSize := CHUNK_SIZE
		if offset+int64(blockSize) > fileSize {
			blockSize = int(fileSize - offset)
		}
		chunk := make([]byte, blockSize)
		_, err = inputFile.ReadAt(chunk, offset)
		if err != nil {
			return fmt.Errorf("读取文件块失败: %v", err)
		}
		encryptedChunk := make([]byte, blockSize)
		stream.XORKeyStream(encryptedChunk, chunk)
		_, err = outputFile.Write(encryptedChunk)
		if err != nil {
			return fmt.Errorf("写入加密数据失败: %v", err)
		}
		fileBlocks = append(fileBlocks, blockSize)
		offset += int64(blockSize)
		currentChunk++
		if showProgress {
			progress := int(float64(currentChunk) / float64(totalChunks) * 100)
			fmt.Printf("\r加密进度: %d%%", progress)
		}
	}
	if showProgress {
		fmt.Println()
	}

	// 生成文件参数
	pwdSign := generatePasswordSign(password)
	fileParams := FileInfo{
		Version:      2,
		FileName:     filepath.Base(inputPath),
		FileSize:     fileSize,
		PasswordSign: pwdSign,
		BlockSizes:   fileBlocks,
	}

	// 序列化参数
	paramsJSON, err := json.Marshal(fileParams)
	if err != nil {
		return fmt.Errorf("序列化文件参数失败: %v", err)
	}

	// Base64编码参数
	paramsBase64 := base64.StdEncoding.EncodeToString(paramsJSON)
	footer := paramsBase64 + "|" + strconv.Itoa(len(paramsBase64))
	_, err = outputFile.WriteString(footer)
	if err != nil {
		return fmt.Errorf("写入文件尾部失败: %v", err)
	}

	return nil
}

// 解密文件
func DecryptFile(inputPath, outputPath, password string, showProgress bool) error {
	// 打开输入文件
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %v", err)
	}
	defer inputFile.Close()

	// 获取文件信息
	stat, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %v", err)
	}
	fileSize := stat.Size()

	// 验证文件头
	header := make([]byte, 60)
	_, err = inputFile.ReadAt(header, 0)
	if err != nil {
		return fmt.Errorf("读取文件头失败: %v", err)
	}

	headerText := string(header)
	if !strings.HasPrefix(headerText, "[hkef]") {
		return fmt.Errorf("不是有效的加密文件")
	}

	// 读取文件末尾20个字符来寻找参数长度分隔符
	tailBuffer := make([]byte, 20)
	_, err = inputFile.ReadAt(tailBuffer, fileSize-20)
	if err != nil {
		return fmt.Errorf("读取文件尾部失败: %v", err)
	}

	tailText := string(tailBuffer)
	lastPipeIndex := strings.LastIndex(tailText, "|")
	if lastPipeIndex == -1 {
		return fmt.Errorf("文件格式错误：未找到参数分隔符")
	}

	// 获取参数base64的长度
	base64LenStr := tailText[lastPipeIndex+1:]
	base64Len, err := strconv.Atoi(base64LenStr)
	if err != nil || base64Len <= 0 {
		return fmt.Errorf("文件格式错误：参数长度无效")
	}

	// 读取参数部分
	paramsBuffer := make([]byte, base64Len)
	paramsOffset := fileSize - 20 + int64(lastPipeIndex) - int64(base64Len)
	_, err = inputFile.ReadAt(paramsBuffer, paramsOffset)
	if err != nil {
		return fmt.Errorf("读取文件参数失败: %v", err)
	}

	paramsBase64 := string(paramsBuffer)
	paramsJSON, err := base64.StdEncoding.DecodeString(paramsBase64)
	if err != nil {
		return fmt.Errorf("解码文件参数失败: %v", err)
	}

	// 解析文件参数
	var fileParams FileInfo
	err = json.Unmarshal(paramsJSON, &fileParams)
	if err != nil {
		return fmt.Errorf("解析文件参数失败: %v", err)
	}

	// 验证密码
	pwdSign := generatePasswordSign(password)
	if pwdSign != fileParams.PasswordSign {
		return fmt.Errorf("密码错误")
	}

	// 生成密钥和IV
	key, iv, err := generateKeyAndIV(password)
	if err != nil {
		return fmt.Errorf("生成密钥失败: %v", err)
	}

	// 创建输出文件
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outputFile.Close()

	// 创建AES-CTR解密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("创建AES解密器失败: %v", err)
	}
	stream := cipher.NewCTR(block, iv)

	// 跳过文件头 [hkef][md5Sign][v3]
	currentPos := int64(24) // 6 + 14 + 4
	totalProcessed := int64(0)
	encryptedDataSize := fileSize - 24 - int64(base64Len+lastPipeIndex+1)

	// 分块解密文件内容
	for _, blockLen := range fileParams.BlockSizes {
		encryptedBuffer := make([]byte, blockLen)
		_, err = inputFile.ReadAt(encryptedBuffer, currentPos)
		if err != nil {
			return fmt.Errorf("读取加密块失败: %v", err)
		}
		decryptedChunk := make([]byte, blockLen)
		stream.XORKeyStream(decryptedChunk, encryptedBuffer)
		_, err = outputFile.Write(decryptedChunk)
		if err != nil {
			return fmt.Errorf("写入解密数据失败: %v", err)
		}
		currentPos += int64(blockLen)
		totalProcessed += int64(blockLen)
		if showProgress {
			progress := int(float64(totalProcessed) / float64(encryptedDataSize) * 100)
			fmt.Printf("\r解密进度: %d%%", progress)
		}
	}
	if showProgress {
		fmt.Println()
	}

	// 验证解密后的文件大小
	outputStat, err := outputFile.Stat()
	if err != nil {
		return fmt.Errorf("获取输出文件信息失败: %v", err)
	}

	if outputStat.Size() != fileParams.FileSize {
		return fmt.Errorf("文件解密错误：大小不匹配")
	}

	return nil
}

// 获取文件信息
func GetFileInfo(inputPath string) (*FileInfo, error) {
	// 打开输入文件
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("打开输入文件失败: %v", err)
	}
	defer inputFile.Close()

	// 获取文件信息
	stat, err := inputFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("获取文件信息失败: %v", err)
	}
	fileSize := stat.Size()

	// 读取文件头 [hkef][md5Sign][v1/v2/v3]
	header := make([]byte, 60)
	_, err = inputFile.ReadAt(header, 0)
	if err != nil {
		return nil, fmt.Errorf("读取文件头失败: %v", err)
	}

	headerText := string(header)
	if !strings.HasPrefix(headerText, "[hkef]") {
		return nil, fmt.Errorf("不是有效的加密文件")
	}

	// 解析版本信息
	versionMatch := strings.Index(headerText, "[v")
	if versionMatch == -1 {
		return nil, fmt.Errorf("文件格式错误：未找到版本信息")
	}
	versionEnd := strings.Index(headerText[versionMatch:], "]")
	if versionEnd == -1 {
		return nil, fmt.Errorf("文件格式错误：版本信息格式错误")
	}
	versionStr := headerText[versionMatch+2 : versionMatch+versionEnd]
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		return nil, fmt.Errorf("文件格式错误：版本号无效")
	}

	// 解析MD5签名
	md5Start := strings.Index(headerText, "[")
	if md5Start == -1 {
		return nil, fmt.Errorf("文件格式错误：未找到MD5签名")
	}
	md5End := strings.Index(headerText[md5Start+1:], "]")
	if md5End == -1 {
		return nil, fmt.Errorf("文件格式错误：MD5签名格式错误")
	}
	md5Sign := headerText[md5Start+1 : md5Start+1+md5End]

	// 读取文件末尾20个字符来寻找参数长度分隔符
	tailBuffer := make([]byte, 20)
	_, err = inputFile.ReadAt(tailBuffer, fileSize-20)
	if err != nil {
		return nil, fmt.Errorf("读取文件尾部失败: %v", err)
	}

	tailText := string(tailBuffer)
	lastPipeIndex := strings.LastIndex(tailText, "|")
	if lastPipeIndex == -1 {
		return nil, fmt.Errorf("文件格式错误：未找到参数分隔符")
	}

	// 获取参数base64的长度
	base64LenStr := tailText[lastPipeIndex+1:]
	base64Len, err := strconv.Atoi(base64LenStr)
	if err != nil || base64Len <= 0 {
		return nil, fmt.Errorf("文件格式错误：参数长度无效")
	}

	// 读取参数部分
	paramsBuffer := make([]byte, base64Len)
	paramsOffset := fileSize - 20 + int64(lastPipeIndex) - int64(base64Len)
	_, err = inputFile.ReadAt(paramsBuffer, paramsOffset)
	if err != nil {
		return nil, fmt.Errorf("读取文件参数失败: %v", err)
	}

	paramsBase64 := string(paramsBuffer)
	paramsJSON, err := base64.StdEncoding.DecodeString(paramsBase64)
	if err != nil {
		return nil, fmt.Errorf("解码文件参数失败: %v", err)
	}

	// 解析文件参数
	var fileParams FileInfo
	err = json.Unmarshal(paramsJSON, &fileParams)
	if err != nil {
		return nil, fmt.Errorf("解析文件参数失败: %v", err)
	}

	// 设置额外信息
	fileParams.Version = version
	fileParams.MD5Sign = md5Sign
	fileParams.EncryptedSize = fileSize - 24 - int64(base64Len+lastPipeIndex+1)

	return &fileParams, nil
}

// min函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
