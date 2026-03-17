/**
 * Alerts Page
 * Security alert management
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
  message,
  Descriptions,
} from 'antd'
import {
  ReloadOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  EyeOutlined,
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import api from '@/services/api'

interface Alert {
  id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'investigating' | 'resolved' | 'false_positive'
  category: string
  source: string
  created_at: string
  updated_at: string
  resolved_at?: string
  metadata: any
}

const Alerts = () => {
  const [loading, setLoading] = useState(false)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [detailModalVisible, setDetailModalVisible] = useState(false)
  const [resolveModalVisible, setResolveModalVisible] = useState(false)
  const [resolveNotes, setResolveNotes] = useState('')

  useEffect(() => {
    fetchAlerts()
  }, [])

  const fetchAlerts = async () => {
    setLoading(true)
    try {
      const data = await api.getAlerts()
      setAlerts(data)
    } catch (error) {
      message.error('加载告警失败')
    } finally {
      setLoading(false)
    }
  }

  const handleResolve = async () => {
    if (!selectedAlert) return

    try {
      await api.resolveAlert(selectedAlert.id, resolveNotes)
      message.success('告警已标记为已解决')
      setResolveModalVisible(false)
      setResolveNotes('')
      fetchAlerts()
    } catch (error) {
      message.error('操作失败')
    }
  }

  const viewDetail = (alert: Alert) => {
    setSelectedAlert(alert)
    setDetailModalVisible(true)
  }

  const openResolveModal = (alert: Alert) => {
    setSelectedAlert(alert)
    setResolveModalVisible(true)
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <CloseCircleOutlined style={{ color: '#ff4d4f' }} />
      case 'high':
        return <ExclamationCircleOutlined style={{ color: '#ff7a45' }} />
      case 'medium':
        return <ExclamationCircleOutlined style={{ color: '#ffa940' }} />
      default:
        return <ExclamationCircleOutlined style={{ color: '#52c41a' }} />
    }
  }

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: '#ff4d4f',
      high: '#ff7a45',
      medium: '#ffa940',
      low: '#52c41a',
    }
    return colors[severity] || '#d9d9d9'
  }

  const getStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      open: '#ff4d4f',
      investigating: '#ffa940',
      resolved: '#52c41a',
      false_positive: '#d9d9d9',
    }
    return colors[status] || '#d9d9d9'
  }

  const columns: ColumnsType<Alert> = [
    {
      title: '级别',
      dataIndex: 'severity',
      key: 'severity',
      width: 80,
      render: (severity) => (
        <Tag icon={getSeverityIcon(severity)} color={getSeverityColor(severity)}>
          {severity.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: '标题',
      dataIndex: 'title',
      key: 'title',
      ellipsis: true,
    },
    {
      title: '类别',
      dataIndex: 'category',
      key: 'category',
      width: 150,
      render: (category) => <Tag>{category}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status) => (
        <Tag color={getStatusColor(status)}>
          {status === 'open' && '待处理'}
          {status === 'investigating' && '调查中'}
          {status === 'resolved' && '已解决'}
          {status === 'false_positive' && '误报'}
        </Tag>
      ),
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 120,
    },
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (time) => new Date(time).toLocaleString('zh-CN'),
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EyeOutlined />} onClick={() => viewDetail(record)}>
            详情
          </Button>
          {record.status === 'open' && (
            <Button
              size="small"
              type="primary"
              icon={<CheckCircleOutlined />}
              onClick={() => openResolveModal(record)}
            >
              解决
            </Button>
          )}
        </Space>
      ),
    },
  ]

  return (
    <div>
      <Card
        title="告警中心"
        extra={
          <Button icon={<ReloadOutlined />} onClick={fetchAlerts}>
            刷新
          </Button>
        }
      />

      <Card style={{ marginTop: 16 }}>
        <Table
          columns={columns}
          dataSource={alerts}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 20, showSizeChanger: true }}
        />
      </Card>

      {/* Detail Modal */}
      <Modal
        title="告警详情"
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setDetailModalVisible(false)}>
            关闭
          </Button>,
          selectedAlert?.status === 'open' && (
            <Button
              key="resolve"
              type="primary"
              icon={<CheckCircleOutlined />}
              onClick={() => {
                setDetailModalVisible(false)
                openResolveModal(selectedAlert)
              }}
            >
              标记为已解决
            </Button>
          ),
        ]}
        width={700}
      >
        {selectedAlert && (
          <Descriptions column={1} bordered>
            <Descriptions.Item label="告警ID">{selectedAlert.id}</Descriptions.Item>
            <Descriptions.Item label="标题">{selectedAlert.title}</Descriptions.Item>
            <Descriptions.Item label="描述">{selectedAlert.description}</Descriptions.Item>
            <Descriptions.Item label="级别">
              <Tag color={getSeverityColor(selectedAlert.severity)}>
                {selectedAlert.severity.toUpperCase()}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="类别">{selectedAlert.category}</Descriptions.Item>
            <Descriptions.Item label="来源">{selectedAlert.source}</Descriptions.Item>
            <Descriptions.Item label="状态">
              <Tag color={getStatusColor(selectedAlert.status)}>{selectedAlert.status}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="创建时间">
              {new Date(selectedAlert.created_at).toLocaleString('zh-CN')}
            </Descriptions.Item>
            <Descriptions.Item label="元数据">
              <pre>{JSON.stringify(selectedAlert.metadata, null, 2)}</pre>
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>

      {/* Resolve Modal */}
      <Modal
        title="解决告警"
        open={resolveModalVisible}
        onCancel={() => setResolveModalVisible(false)}
        onOk={handleResolve}
        okText="确认解决"
      >
        <Form layout="vertical">
          <Form.Item label="备注说明">
            <Input.TextArea
              rows={4}
              placeholder="请输入解决此告警的说明..."
              value={resolveNotes}
              onChange={(e) => setResolveNotes(e.target.value)}
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default Alerts
