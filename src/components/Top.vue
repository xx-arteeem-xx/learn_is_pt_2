<script>
import Header from './Header/Header.vue';
import { api } from '@/utils/api';

export default {
    components: {
        Header
    },
    data() {
        return {
            keySize: 1024,
            fileInfo: {
                name: '',
                data: null
            },
            keyInfo: {
                name: '',
                data: null
            },
            rc4FileInfo: {
                name: '',
                data: null
            },
            rc4Key: '',
            operationResult: '',
            operationError: '',
            encryptedData: null
        }
    },
    computed: {
        canProcessVernam() {
            return this.fileInfo.data && this.keyInfo.data
        },
        canProcessRc4() {
            return this.rc4FileInfo.data && this.rc4Key.length > 0
        }
    },
    methods: {
        generateKeyFile() {
            const keyArray = new Uint8Array(this.keySize)
            window.crypto.getRandomValues(keyArray)
            this.downloadFile(keyArray, 'vernam_key.bin')
            this.operationResult = `Ключ размером ${this.keySize} байт успешно сгенерирован и скачан`
            this.operationError = ''
        },

        handleFileUpload(event) {
            const file = event.target.files[0]
            if (!file) return

            this.fileInfo.name = file.name
            const reader = new FileReader()
            reader.onload = (e) => {
                this.fileInfo.data = new Uint8Array(e.target.result)
            }
            reader.readAsArrayBuffer(file)
            this.clearMessages()
        },

        handleKeyUpload(event) {
            const file = event.target.files[0]
            if (!file) return

            this.keyInfo.name = file.name
            const reader = new FileReader()
            reader.onload = (e) => {
                this.keyInfo.data = new Uint8Array(e.target.result)
            }
            reader.readAsArrayBuffer(file)
            this.clearMessages()
        },

        handleRc4FileUpload(event) {
            const file = event.target.files[0]
            if (!file) return

            this.rc4FileInfo.name = file.name
            const reader = new FileReader()
            reader.onload = (e) => {
                this.rc4FileInfo.data = new Uint8Array(e.target.result)
            }
            reader.readAsArrayBuffer(file)
            this.clearMessages()
        },

        vernamEncrypt() {
            if (!this.validateFileSizes()) return

            const result = new Uint8Array(this.fileInfo.data.length)
            for (let i = 0; i < this.fileInfo.data.length; i++) {
                result[i] = this.fileInfo.data[i] ^ this.keyInfo.data[i]
            }

            this.downloadFile(result, 'encrypted_vernam.bin')
            this.operationResult = 'Файл успешно зашифрован методом Вернама'
            this.operationError = ''
        },

        vernamDecrypt() {
            if (!this.validateFileSizes()) return

            const result = new Uint8Array(this.fileInfo.data.length)
            for (let i = 0; i < this.fileInfo.data.length; i++) {
                result[i] = this.fileInfo.data[i] ^ this.keyInfo.data[i]
            }

            this.downloadFile(result, 'decrypted_vernam.bin')
            this.operationResult = 'Файл успешно расшифрован методом Вернама'
            this.operationError = ''
        },

        validateFileSizes() {
            if (this.fileInfo.data.length > this.keyInfo.data.length) {
                this.operationError = 'Ошибка: ключевой файл должен быть не меньше исходного файла'
                this.operationResult = ''
                return false
            }
            return true
        },

        rc4Encrypt() {
            try {
                const result = this.rc4Process(this.rc4FileInfo.data, this.rc4Key);
                this.downloadFile(result, 'encrypted_rc4.bin');
                this.operationResult = 'Файл успешно зашифрован методом RC4';
                this.operationError = '';

                this.encryptedData = result;
            } catch (error) {
                this.operationError = 'Ошибка при шифровании: ' + error.message;
                this.operationResult = '';
            }
        },

        rc4Decrypt() {
            try {
                const result = this.rc4Process(this.rc4FileInfo.data, this.rc4Key);
                this.downloadFile(result, 'decrypted_rc4.bin');
                this.operationResult = 'Файл успешно расшифрован методом RC4';
                this.operationError = '';
            } catch (error) {
                this.operationError = 'Ошибка при расшифровании: ' + error.message;
                this.operationResult = '';
            }
        },

        rc4Process(data, key) {
            const keyBytes = new Uint8Array(key.length);
            for (let i = 0; i < key.length; i++) {
                keyBytes[i] = key.charCodeAt(i) & 0xFF;
            }

            const S = new Array(256);
            for (let i = 0; i < 256; i++) {
                S[i] = i;
            }

            let j = 0;
            for (let i = 0; i < 256; i++) {
                j = (j + S[i] + keyBytes[i % keyBytes.length]) % 256;
                const temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            const result = new Uint8Array(data.length);
            let i = 0;
            j = 0;

            for (let k = 0; k < data.length; k++) {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;

                const temp = S[i];
                S[i] = S[j];
                S[j] = temp;

                const K = S[(S[i] + S[j]) % 256];
                result[k] = data[k] ^ K;
            }

            return result;
        },

        downloadFile(data, filename) {
            const blob = new Blob([data], { type: 'application/octet-stream' })
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = filename
            document.body.appendChild(a)
            a.click()
            document.body.removeChild(a)
            URL.revokeObjectURL(url)
        },

        clearMessages() {
            this.operationResult = ''
            this.operationError = ''
        }
    }
}
</script>

<template>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <div class="card shadow mb-4">
                    <div class="card-header bg-primary text-white">
                        <h1 class="h4 mb-0">
                            <i class="fas fa-lock me-2"></i>
                            Шифр Вернама и поточные шифры
                        </h1>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card shadow mb-4">
                    <div class="card-header bg-success text-white">
                        <h2 class="h5 mb-0">
                            <i class="fas fa-key me-2"></i>
                            Генерация ключа
                        </h2>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label class="form-label">Размер ключа (байт):</label>
                            <input type="number" class="form-control" v-model.number="keySize" min="1" max="100000">
                        </div>
                        <button class="btn btn-success w-100" @click="generateKeyFile">
                            <i class="fas fa-download me-2"></i>Сгенерировать и скачать ключ
                        </button>
                    </div>
                </div>

                <div class="card shadow mb-4">
                    <div class="card-header bg-info text-white">
                        <h2 class="h5 mb-0">
                            <i class="fas fa-exchange-alt me-2"></i>
                            Шифр Вернама (XOR)
                        </h2>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label class="form-label">Исходный файл:</label>
                            <input type="file" class="form-control" @change="handleFileUpload" ref="fileInput">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Ключевой файл:</label>
                            <input type="file" class="form-control" @change="handleKeyUpload" ref="keyInput">
                        </div>
                        <div class="d-grid gap-2">
                            <button class="btn btn-info" @click="vernamEncrypt" :disabled="!canProcessVernam">
                                <i class="fas fa-lock me-2"></i>Зашифровать
                            </button>
                            <button class="btn btn-warning" @click="vernamDecrypt" :disabled="!canProcessVernam">
                                <i class="fas fa-unlock me-2"></i>Расшифровать
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card shadow mb-4">
                    <div class="card-header bg-danger text-white">
                        <h2 class="h5 mb-0">
                            <i class="fas fa-random me-2"></i>
                            Поточный шифр RC4
                        </h2>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label class="form-label">Исходный файл:</label>
                            <input type="file" class="form-control" @change="handleRc4FileUpload" ref="rc4FileInput">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Ключ (строка):</label>
                            <input type="text" class="form-control" v-model="rc4Key"
                                placeholder="Введите ключевую фразу">
                        </div>
                        <div class="d-grid gap-2">
                            <button class="btn btn-danger" @click="rc4Encrypt" :disabled="!canProcessRc4">
                                <i class="fas fa-lock me-2"></i>Зашифровать RC4
                            </button>
                            <button class="btn btn-secondary" @click="rc4Decrypt" :disabled="!canProcessRc4">
                                <i class="fas fa-unlock me-2"></i>Расшифровать RC4
                            </button>
                        </div>
                    </div>
                </div>

                <div class="card shadow">
                    <div class="card-header bg-dark text-white">
                        <h2 class="h5 mb-0">
                            <i class="fas fa-info-circle me-2"></i>
                            Информация
                        </h2>
                    </div>
                    <div class="card-body">
                        <div v-if="operationResult" class="alert alert-success">
                            <i class="fas fa-check me-2"></i>
                            {{ operationResult }}
                        </div>
                        <div v-if="operationError" class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            {{ operationError }}
                        </div>

                        <div class="mt-3">
                            <h6 class="text-muted">Статус файлов:</h6>
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item d-flex justify-content-between align-items-center">
                                    Исходный файл
                                    <span class="badge" :class="fileInfo.name ? 'bg-success' : 'bg-secondary'">
                                        {{ fileInfo.name || 'Не выбран' }}
                                    </span>
                                </li>
                                <li class="list-group-item d-flex justify-content-between align-items-center">
                                    Ключевой файл
                                    <span class="badge" :class="keyInfo.name ? 'bg-success' : 'bg-secondary'">
                                        {{ keyInfo.name || 'Не выбран' }}
                                    </span>
                                </li>
                                <li class="list-group-item d-flex justify-content-between align-items-center">
                                    Файл для RC4
                                    <span class="badge" :class="rc4FileInfo.name ? 'bg-success' : 'bg-secondary'">
                                        {{ rc4FileInfo.name || 'Не выбран' }}
                                    </span>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<style>
.card {
    border: none;
    border-radius: 10px;
}

.list-group-item {
    border: none;
    padding: 0.5rem 0;
}

.badge {
    font-size: 0.75em;
}
</style>