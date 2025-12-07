import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';
import { Pool } from 'pg'; // Cài đặt adapter pg
import { PrismaPg } from '@prisma/adapter-pg';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {

    // Khai báo thuộc tính config ở đây (không có private/public)
    private config: ConfigService;

    // 1. Thay đổi tham số thành config: ConfigService (bỏ 'private')
    constructor(config: ConfigService) {

        // 2. Lấy URL và tạo Adapter BẰNG CÁCH SỬ DỤNG THAM SỐ TRỰC TIẾP
        const url = config.get<string>('DATABASE_URL');
        const pool = new Pool({ connectionString: url });
        const adapter = new PrismaPg(pool);

        // 3. GỌI SUPER() ĐẦU TIÊN
        super({
            adapter: adapter,
            log: ['query'],
        });

        // 4. CHỈ SAU KHI SUPER() được gọi, bạn mới gán thuộc tính cho 'this'
        this.config = config;
    }

    async onModuleInit() {
        // Đảm bảo kết nối được mở
        await this.$connect();
    }

    async onModuleDestroy() {
        // Đảm bảo kết nối được đóng
        await this.$disconnect();
    }

    // Hàm cleanDb (ví dụ)
    cleanDb() {
        return this.$transaction([
            this.rolePermission.deleteMany(),
            this.userRole.deleteMany(),
            this.permission.deleteMany(),
            this.role.deleteMany(),
            this.user.deleteMany(),
        ]);
    }
}