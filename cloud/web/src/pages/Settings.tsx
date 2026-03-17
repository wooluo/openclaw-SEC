/**
 * Settings Page
 * System configuration
 */

import React, { useState } from 'react'
import { Card, Form, Input, Switch, Button, InputNumber, message, Tabs, Divider } from 'antd'
import { SaveOutlined, ReloadOutlined } from '@ant-design/icons'

const Settings = () => {
  const [form] = Form.useForm()
  const [loading, setLoading] = useState(false)

  const handleSave = async (values: any) => {
    setLoading(true)
    // Simulate API call
    setTimeout(() => {
      setLoading(false)
      message.success('设置已保存')
    }, 1000)
  }

  return (
    <div>
      <Card title="系统设置">
        <Tabs
          defaultActiveKey="general"
          items={[
            {
              key: 'general',
              label: '基本设置',
              children: (
                <Form
                  form={form}
                  layout="vertical"
                  initialValues={{
                    scanOnInstall: true,
                    blockMalicious: true,
                    autoUpdate: true,
                  }}
                  onFinish={handleSave}
                >
                  <Form.Item
                    name="scanOnInstall"
                    label="安装时扫描"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>

                  <Form.Item
                    name="blockMalicious"
                    label="自动拦截恶意文件"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>

                  <Form.Item
                    name="autoUpdate"
                    label="自动更新规则库"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>

                  <Form.Item
                    name="logLevel"
                    label="日志级别"
                  >
                    <Select>
                      <Select.Option value="DEBUG">DEBUG</Select.Option>
                      <Select.Option value="INFO">INFO</Select.Option>
                      <Select.Option value="WARNING">WARNING</Select.Option>
                      <Select.Option value="ERROR">ERROR</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item style={{ marginTop: 16 }}>
                    <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={loading}>
                      保存设置
                    </Button>
                  </Form.Item>
                </Form>
              ),
            },
            {
              key: 'detection',
              label: '检测规则',
              children: (
                <Form
                  layout="vertical"
                  initialValues={{
                    sensitivity: 'high',
                    enableAIAnalysis: true,
                    enablePromptDetection: true,
                  }}
                >
                  <Form.Item
                    name="sensitivity"
                    label="检测敏感度"
                  >
                    <Select>
                      <Select.Option value="low">低</Select.Option>
                      <Select.Option value="medium">中</Select.Option>
                      <Select.Option value="high">高</Select.Option>
                    </Select>
                  </Form.Item>

                  <Form.Item
                    name="enableAIAnalysis"
                    label="AI流量分析"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>

                  <Form.Item
                    name="enablePromptDetection"
                    label="Prompt注入检测"
                    valuePropName="checked"
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>

                  <Divider />

                  <Form.Item label="API密钥检测">
                    <Input.TextArea rows={4} placeholder='输入正则表达式模式，每行一个' />
                  </Form.Item>

                  <Form.Item>
                    <Button type="primary" icon={<SaveOutlined />}>
                      保存规则
                    </Button>
                  </Form.Item>
                </Form>
              ),
            },
            {
              key: 'network',
              label: '网络监控',
              children: (
                <Form layout="vertical">
                  <Form.Item
                    name="enableNetworkMonitoring"
                    label="启用网络监控"
                    valuePropName="checked"
                    initialValue={true}
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>

                  <Form.Item
                    name="autoBlockSuspicious"
                    label="自动拦截可疑连接"
                    valuePropName="checked"
                    initialValue={true}
                  >
                    <Switch checkedChildren="启用" unCheckedChildren="禁用" />
                  </Form.Item>

                  <Form.Item label="信任域名">
                    <Input.TextArea rows={3} placeholder='每行一个域名，例如：api.openai.com' />
                  </Form.Item>

                  <Form.Item label="拦截域名">
                    <Input.TextArea rows={3} placeholder='每行一个域名' />
                  </Form.Item>

                  <Form.Item>
                    <Button type="primary" icon={<SaveOutlined />}>
                      保存设置
                    </Button>
                  </Form.Item>
                </Form>
              ),
            },
            {
              key: 'notifications',
              label: '通知设置',
              children: (
                <Form layout="vertical">
                  <Form.Item
                    name="enableAlerts"
                    label="启用告警通知"
                    valuePropName="checked"
                    initialValue={true}
                  >
                    <Switch />
                  </Form.Item>

                  <Form.Item
                    name="alertEmail"
                    label="告警邮箱"
                  >
                    <Input placeholder="输入接收告警的邮箱地址" />
                  </Form.Item>

                  <Form.Item
                    name="alertWebhook"
                    label="Webhook URL"
                  >
                    <Input placeholder="输入Webhook URL用于告警推送" />
                  </Form.Item>

                  <Form.Item>
                    <Button type="primary" icon={<SaveOutlined />}>
                      保存设置
                    </Button>
                  </Form.Item>
                </Form>
              ),
            },
          ]}
        />
      </Card>
    </div>
  )
}

export default Settings
