/**
 * Policies Page
 * Security policy management
 */

import React, { useState, useEffect } from 'react'
import {
  Table,
  Card,
  Button,
  Tag,
  Space,
  Modal,
  Form,
  Input,
  Select,
  Switch,
  message,
} from 'antd'
import {
  ReloadOutlined,
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import api from '@/services/api'

interface Policy {
  id: string
  name: string
  description: string
  category: string
  enabled: boolean
  rules: any
  created_at: string
  updated_at: string
}

const Policies = () => {
  const [loading, setLoading] = useState(false)
  const [policies, setPolicies] = useState<Policy[]>([])
  const [modalVisible, setModalVisible] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null)
  const [form] = Form.useForm()

  useEffect(() => {
    fetchPolicies()
  }, [])

  const fetchPolicies = async () => {
    setLoading(true)
    try {
      const data = await api.getPolicies()
      setPolicies(data)
    } catch (error) {
      message.error('加载策略失败')
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = () => {
    setEditingPolicy(null)
    form.resetFields()
    setModalVisible(true)
  }

  const handleEdit = (policy: Policy) => {
    setEditingPolicy(policy)
    form.setFieldsValue(policy)
    setModalVisible(true)
  }

  const handleDelete = async (id: string) => {
    Modal.confirm({
      title: '确认删除',
      content: '确定要删除此策略吗？',
      onOk: async () => {
        try {
          await api.deletePolicy(id)
          message.success('策略已删除')
          fetchPolicies()
        } catch (error) {
          message.error('删除失败')
        }
      },
    })
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()

      if (editingPolicy) {
        await api.updatePolicy(editingPolicy.id, values)
        message.success('策略已更新')
      } else {
        await api.createPolicy(values)
        message.success('策略已创建')
      }

      setModalVisible(false)
      fetchPolicies()
    } catch (error) {
      message.error('操作失败')
    }
  }

  const handleToggle = async (policy: Policy) => {
    try {
      await api.updatePolicy(policy.id, { enabled: !policy.enabled })
      message.success('策略已更新')
      fetchPolicies()
    } catch (error) {
      message.error('更新失败')
    }
  }

  const columns: ColumnsType<Policy> = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: '类别',
      dataIndex: 'category',
      key: 'category',
      render: (category) => <Tag>{category}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 100,
      render: (enabled, record) => (
        <Switch
          checked={enabled}
          onChange={() => handleToggle(record)}
          checkedChildren="启用"
          unCheckedChildren="禁用"
        />
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      key: 'updated_at',
      width: 180,
      render: (time) => new Date(time).toLocaleString('zh-CN'),
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
            编辑
          </Button>
          <Button
            size="small"
            danger
            icon={<DeleteOutlined />}
            onClick={() => handleDelete(record.id)}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <Card
        title="策略管理"
        extra={
          <Space>
            <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
              新建策略
            </Button>
            <Button icon={<ReloadOutlined />} onClick={fetchPolicies}>
              刷新
            </Button>
          </Space>
        }
      />

      <Card style={{ marginTop: 16 }}>
        <Table
          columns={columns}
          dataSource={policies}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 20, showSizeChanger: true }}
        />
      </Card>

      <Modal
        title={editingPolicy ? '编辑策略' : '新建策略'}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        onOk={handleSubmit}
        width={600}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="name"
            label="策略名称"
            rules={[{ required: true, message: '请输入策略名称' }]}
          >
            <Input placeholder="请输入策略名称" />
          </Form.Item>

          <Form.Item
            name="category"
            label="策略类别"
            rules={[{ required: true, message: '请选择策略类别' }]}
          >
            <Select placeholder="请选择策略类别">
              <Select.Option value="ai_security">AI安全</Select.Option>
              <Select.Option value="code_security">代码安全</Select.Option>
              <Select.Option value="network_security">网络安全</Select.Option>
              <Select.Option value="access_control">访问控制</Select.Option>
            </Select>
          </Form.Item>

          <Form.Item
            name="description"
            label="描述"
            rules={[{ required: true, message: '请输入策略描述' }]}
          >
            <Input.TextArea rows={3} placeholder="请输入策略描述" />
          </Form.Item>

          <Form.Item name="enabled" label="启用状态" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="禁用" />
          </Form.Item>

          <Form.Item label="规则">
            <Input.TextArea
              rows={5}
              placeholder='请输入规则配置 (JSON格式)'
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default Policies
