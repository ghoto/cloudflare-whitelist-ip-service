import { Container, Title, Paper, Button, Select, Text, Center, Stack, Loader, Group, Badge, Alert } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useState, useEffect } from 'react';

interface StatusData {
  ip: string;
  whitelisted: boolean;
  expiresAt?: string;
  timeRemaining?: string;
}

function App() {
  const [submitted, setSubmitted] = useState(false);
  const [status, setStatus] = useState<StatusData | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);

  const form = useForm({
    initialValues: {
      duration: '60',
    },
  });

  const fetchStatus = () => {
    setLoadingStatus(true);
    fetch('/status')
      .then(res => res.json())
      .then(data => {
        setStatus(data);
        setLoadingStatus(false);
      })
      .catch(err => {
        console.error('Failed to fetch status', err);
        setStatus({ ip: 'Unknown', whitelisted: false });
        setLoadingStatus(false);
      });
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleWhitelist = (values: typeof form.values) => {
    setSubmitted(true);
    setActionLoading(true);

    fetch('/whitelist', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ duration: values.duration }),
    })
      .then(res => {
        if (!res.ok) throw new Error('Network response was not ok');
        return res.json();
      })
      .then(data => {
        console.log('Success:', data);
        setTimeout(() => {
          setSubmitted(false);
          setActionLoading(false);
          fetchStatus(); // Refresh status
        }, 1000);
      })
      .catch(error => {
        console.error('Error:', error);
        setSubmitted(false);
        setActionLoading(false);
        alert('Failed to whitelist IP');
      });
  };

  const handleRemove = () => {
    if (!confirm('Are you sure you want to remove your IP from the whitelist?')) {
      return;
    }

    setActionLoading(true);

    fetch('/whitelist', {
      method: 'DELETE',
    })
      .then(res => {
        if (!res.ok) throw new Error('Failed to remove IP');
        return res.json();
      })
      .then(data => {
        console.log('Removed:', data);
        setActionLoading(false);
        fetchStatus(); // Refresh status
      })
      .catch(error => {
        console.error('Error:', error);
        setActionLoading(false);
        alert('Failed to remove IP from whitelist');
      });
  };

  return (
    <Center h="100vh" bg="gray.1">
      <Container size="xs" w="100%">
        <Paper shadow="md" p="xl" radius="md" withBorder>
          <Stack gap="lg">
            <div style={{ textAlign: 'center' }}>
              <Title order={2}>Cloudflare IP Whitelist</Title>
              <Text c="dimmed" size="sm" mt={4}>
                Temporarily allow access to your current IP
              </Text>
              <Text size="md" fw={500} mt={10}>
                {loadingStatus ? <Loader size="xs" type="dots" /> : `Your IP: ${status?.ip}`}
              </Text>
            </div>

            {!loadingStatus && status?.whitelisted && (
              <Alert color="green" title="IP Whitelisted">
                <Text size="sm" mb="xs">
                  Your IP is currently whitelisted
                </Text>
                <Group gap="xs">
                  <Badge color="green" size="lg" style={{ textTransform: 'none' }}>
                    {status.timeRemaining}
                  </Badge>
                  <Text size="xs" c="dimmed">remaining</Text>
                </Group>
                <Group mt="md" grow>
                  <Button
                    variant="light"
                    color="blue"
                    onClick={() => form.onSubmit(handleWhitelist)()}
                    loading={actionLoading}
                  >
                    Extend Time
                  </Button>
                  <Button
                    variant="light"
                    color="red"
                    onClick={handleRemove}
                    loading={actionLoading}
                  >
                    Remove
                  </Button>
                </Group>
              </Alert>
            )}

            {!loadingStatus && !status?.whitelisted && (
              <form onSubmit={form.onSubmit(handleWhitelist)}>
                <Stack gap="md">
                  <Select
                    label="Duration"
                    placeholder="Select duration"
                    data={[
                      { value: '60', label: '1 Hour' },
                      { value: '240', label: '4 Hours' },
                      { value: '480', label: '8 Hours' },
                      { value: '1440', label: '24 Hours' },
                    ]}
                    {...form.getInputProps('duration')}
                  />

                  <Button type="submit" fullWidth loading={submitted || actionLoading} mt="md">
                    Whitelist IP
                  </Button>

                  {submitted && (
                    <Text c="green" size="sm" ta="center">
                      Request sent successfully!
                    </Text>
                  )}
                </Stack>
              </form>
            )}
          </Stack>
        </Paper>
      </Container>
    </Center>
  );
}

export default App;
