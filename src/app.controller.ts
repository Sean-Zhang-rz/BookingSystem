import { Controller, Get, SetMetadata } from '@nestjs/common';
import { AppService } from './app.service';
import { RequireLogin, RequirePermission, UserInfo } from './custom.decorator';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(
    @UserInfo('username') username: string,
    @UserInfo() userInfo,
  ): string {
    console.log(username);
    console.log(userInfo);

    return this.appService.getHello();
  }
}
